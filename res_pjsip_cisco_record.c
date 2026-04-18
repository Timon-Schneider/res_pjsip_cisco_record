/* Copyright (C) 2024 Timon Schneider info@timon-schneider.com
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * res_pjsip_cisco_record.c
 *
 * Intercepts Cisco x-cisco-remotecc StartRecording / StopRecording REFER
 * requests (sent when the user presses the Record softkey on a CP-8xxx)
 * and drives MixMonitor on the active channel so the call is captured to
 * disk.  It also mirrors CUCM's wire behaviour by sending a follow-up
 * out-of-dialog REFER back to the phone whose body carries a
 * <statuslineupdatereq> — that is what makes the phone display show the
 * "Recording" banner and the red Record icon.
 *
 * NOTE (per design): the module always pretends recording succeeded.
 * Even if MixMonitor fails to attach we still signal the phone that
 * recording is active.  This is intentional so the user's UI feedback
 * matches CUCM regardless of server-side recording setup.
 *
 * --- Toggle behaviour --------------------------------------------------
 * In reality the CP-8xxx phone never advances its Record softkey from
 * "Record" to "Stop" — only a very specific (undocumented) CUCM
 * RemoteCC response does that, and we don't emulate it.  As a result
 * every press of the Record softkey arrives at the PBX as another
 * <softkeyevent>StartRecording</softkeyevent>.
 *
 * To give the user a useful "press again to stop" experience the module
 * keeps a per-call-id set of currently-recording calls:
 *   1st StartRecording for a dialog → start MixMonitor + remember.
 *   2nd StartRecording for the same dialog → stop MixMonitor + forget.
 *   StopRecording (rare in practice) → always stops.
 *
 * Recorded files land in /var/spool/asterisk/monitor/ with the pattern
 *   cisco-<call-id>-<epoch>.wav
 */

/* Required for externally-compiled Asterisk modules */
#define AST_MODULE_SELF_SYM __local_ast_module_self

/*** MODULEINFO
    <depend>pjproject</depend>
    <depend>res_pjsip</depend>
    <depend>res_pjsip_session</depend>
    <depend>app_mixmonitor</depend>
    <support_level>extended</support_level>
 ***/

#include "asterisk.h"
#include "asterisk/module.h"
#include "asterisk/res_pjsip.h"
#include "asterisk/res_pjsip_session.h"
#include "asterisk/channel.h"
#include "asterisk/pbx.h"
#include "asterisk/app.h"
#include "asterisk/strings.h"
#include "asterisk/utils.h"
#include "asterisk/logger.h"
#include "asterisk/astobj2.h"
#include "asterisk/linkedlists.h"
#include "asterisk/lock.h"
#include "asterisk/time.h"

#include <pjsip.h>
#include <pjsip_ua.h>
#include <pthread.h>

/* ---------- per-call active-recording set ----------------------------- */
/*
 * Cisco CP-8xxx phones do NOT internally remember that recording is
 * running: every press of the Record softkey sends another
 *   <softkeyevent>StartRecording</softkeyevent>
 * REFER (never a StopRecording) unless the call manager sends back a
 * very specific proprietary RemoteCC response that drives the phone's
 * softkey state machine to "Stop".  We don't emulate that so we keep the toggle state ourselves,
 * keyed by the Cisco dialog's call-id.
 *
 * First StartRecording for a call-id → start MixMonitor + remember it.
 * Subsequent StartRecording for the same call-id → stop MixMonitor +
 * forget it.
 * An explicit StopRecording (in the unlikely event a firmware actually
 * sends one) behaves the same as the "subsequent" case.
 */
struct rec_entry {
    char call_id[256];
    AST_LIST_ENTRY(rec_entry) list;
};

static AST_LIST_HEAD_STATIC(active_recs, rec_entry);

static int rec_is_active(const char *call_id)
{
    struct rec_entry *e;
    int found = 0;
    AST_LIST_LOCK(&active_recs);
    AST_LIST_TRAVERSE(&active_recs, e, list) {
        if (!strcmp(e->call_id, call_id)) {
            found = 1;
            break;
        }
    }
    AST_LIST_UNLOCK(&active_recs);
    return found;
}

static void rec_add(const char *call_id)
{
    struct rec_entry *e;
    AST_LIST_LOCK(&active_recs);
    AST_LIST_TRAVERSE(&active_recs, e, list) {
        if (!strcmp(e->call_id, call_id)) {
            AST_LIST_UNLOCK(&active_recs);
            return; /* already there */
        }
    }
    e = ast_calloc(1, sizeof(*e));
    if (!e) {
        AST_LIST_UNLOCK(&active_recs);
        return;
    }
    ast_copy_string(e->call_id, call_id, sizeof(e->call_id));
    AST_LIST_INSERT_HEAD(&active_recs, e, list);
    AST_LIST_UNLOCK(&active_recs);
}

static void rec_remove(const char *call_id)
{
    struct rec_entry *e;
    AST_LIST_LOCK(&active_recs);
    AST_LIST_TRAVERSE_SAFE_BEGIN(&active_recs, e, list) {
        if (!strcmp(e->call_id, call_id)) {
            AST_LIST_REMOVE_CURRENT(list);
            ast_free(e);
            break;
        }
    }
    AST_LIST_TRAVERSE_SAFE_END;
    AST_LIST_UNLOCK(&active_recs);
}

static void rec_clear_all(void)
{
    struct rec_entry *e;
    AST_LIST_LOCK(&active_recs);
    while ((e = AST_LIST_REMOVE_HEAD(&active_recs, list))) {
        ast_free(e);
    }
    AST_LIST_UNLOCK(&active_recs);
}

/* ---------- helpers (copied from res_pjsip_cisco_conference) ---------- */

static int xml_get(const char *xml, const char *tag, char *out, size_t sz)
{
    char open[256], close[256];
    const char *p, *q;
    size_t len;

    snprintf(open,  sizeof(open),  "<%s>",  tag);
    snprintf(close, sizeof(close), "</%s>", tag);

    p = strstr(xml, open);
    if (!p) return -1;
    p += strlen(open);
    q = strstr(p, close);
    if (!q) return -1;

    len = (size_t)(q - p);
    if (len >= sz) return -1;
    memcpy(out, p, len);
    out[len] = '\0';

    while (len > 0 && (out[len-1] == ' ' || out[len-1] == '\t'
                       || out[len-1] == '\r' || out[len-1] == '\n'))
        out[--len] = '\0';

    return 0;
}

/*
 * phone_tag    = XML <localtag>  = phone's own tag  = Asterisk's remote-tag
 * asterisk_tag = XML <remotetag> = Asterisk's tag   = Asterisk's local-tag
 */
static struct ast_channel *channel_for_dialog(const char *call_id,
    const char *phone_tag, const char *asterisk_tag)
{
    pj_str_t cid  = { (char *)call_id,     (pj_ssize_t)strlen(call_id) };
    pj_str_t ltag = { (char *)asterisk_tag, (pj_ssize_t)strlen(asterisk_tag) };
    pj_str_t rtag = { (char *)phone_tag,    (pj_ssize_t)strlen(phone_tag) };
    pjsip_dialog *dlg;
    struct ast_sip_session *session;
    struct ast_channel *chan = NULL;

    dlg = pjsip_ua_find_dialog(&cid, &ltag, &rtag, PJ_TRUE);
    if (!dlg)
        dlg = pjsip_ua_find_dialog(&cid, &rtag, &ltag, PJ_TRUE);
    if (!dlg) {
        ast_log(LOG_WARNING, "CiscoRecord: dialog not found for call-id='%s'\n", call_id);
        return NULL;
    }

    session = ast_sip_dialog_get_session(dlg);
    pjsip_dlg_dec_lock(dlg);

    if (!session) {
        ast_log(LOG_WARNING, "CiscoRecord: no session for call-id='%s'\n", call_id);
        return NULL;
    }

    if (session->channel)
        chan = ast_channel_ref(session->channel);
    ao2_ref(session, -1);

    if (!chan)
        ast_log(LOG_WARNING, "CiscoRecord: no channel in session for call-id='%s'\n", call_id);

    return chan;
}

/* ---------- refer-NOTIFY (RFC 3515) ------------------------------------
 *
 * Same pattern as the conference module: when we 202 Accept the phone's
 * REFER a fresh implicit subscription is born; we immediately terminate it
 * with a stateless NOTIFY so the Record softkey unlocks.
 */
static void cisco_rec_send_refer_notify(pjsip_rx_data *rdata,
                                        const pj_str_t *local_tag)
{
    static const pjsip_method notify_method = {
        PJSIP_OTHER_METHOD,
        { "NOTIFY", 6 }
    };
    pjsip_endpoint *endpt = ast_sip_get_pjsip_endpoint();
    pjsip_msg *msg = rdata->msg_info.msg;
    pjsip_from_hdr *refer_from = rdata->msg_info.from;
    pjsip_to_hdr   *refer_to   = rdata->msg_info.to;
    pjsip_cid_hdr  *refer_cid  = rdata->msg_info.cid;
    pjsip_contact_hdr *refer_contact;
    pjsip_transport *tp = rdata->tp_info.transport;
    pjsip_tx_data *tdata;
    pj_status_t status;
    pj_str_t target_s, from_s, to_s, contact_s, call_id_s;
    pj_str_t hname, hval;
    char target_buf[256], from_buf[512], to_buf[512];
    char contact_buf[256];
    int n;

    if (!refer_from || !refer_to || !refer_cid || !tp || !local_tag
        || local_tag->slen == 0) {
        ast_log(LOG_WARNING,
            "CiscoRecord: cannot send refer-NOTIFY (missing headers/tag)\n");
        return;
    }

    refer_contact = (pjsip_contact_hdr *)pjsip_msg_find_hdr(msg,
        PJSIP_H_CONTACT, NULL);

    n = pjsip_uri_print(PJSIP_URI_IN_REQ_URI,
        refer_contact ? refer_contact->uri
                      : pjsip_uri_get_uri(refer_from->uri),
        target_buf, sizeof(target_buf) - 1);
    if (n <= 0) return;
    target_buf[n] = '\0';
    target_s.ptr = target_buf; target_s.slen = n;

    n = pjsip_uri_print(PJSIP_URI_IN_FROMTO_HDR, refer_to->uri,
        from_buf, sizeof(from_buf) - 1);
    if (n <= 0) return;
    from_buf[n] = '\0';
    from_s.ptr = from_buf; from_s.slen = n;

    n = pjsip_uri_print(PJSIP_URI_IN_FROMTO_HDR, refer_from->uri,
        to_buf, sizeof(to_buf) - 1);
    if (n <= 0) return;
    to_buf[n] = '\0';
    to_s.ptr = to_buf; to_s.slen = n;

    n = snprintf(contact_buf, sizeof(contact_buf),
        "<sip:%.*s:%d>",
        (int)tp->local_name.host.slen, tp->local_name.host.ptr,
        tp->local_name.port);
    contact_s.ptr = contact_buf; contact_s.slen = n;

    call_id_s = refer_cid->id;

    status = pjsip_endpt_create_request(endpt, &notify_method,
        &target_s, &from_s, &to_s, &contact_s, &call_id_s,
        -1, NULL, &tdata);
    if (status != PJ_SUCCESS) {
        ast_log(LOG_WARNING,
            "CiscoRecord: pjsip_endpt_create_request(NOTIFY) failed: %d\n", status);
        return;
    }

    {
        pjsip_from_hdr *f = (pjsip_from_hdr *)pjsip_msg_find_hdr(tdata->msg,
            PJSIP_H_FROM, NULL);
        pjsip_to_hdr   *t = (pjsip_to_hdr *)pjsip_msg_find_hdr(tdata->msg,
            PJSIP_H_TO,   NULL);
        if (f) pj_strdup(tdata->pool, &f->tag, local_tag);
        if (t) pj_strdup(tdata->pool, &t->tag, &refer_from->tag);
    }

    hname = pj_str("Event");
    hval  = pj_str("refer");
    pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr *)
        pjsip_generic_string_hdr_create(tdata->pool, &hname, &hval));

    hname = pj_str("Subscription-State");
    hval  = pj_str("terminated;reason=noresource");
    pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr *)
        pjsip_generic_string_hdr_create(tdata->pool, &hname, &hval));

    status = pjsip_endpt_send_request_stateless(endpt, tdata, NULL, NULL);
    if (status != PJ_SUCCESS) {
        ast_log(LOG_WARNING,
            "CiscoRecord: pjsip_endpt_send_request_stateless(NOTIFY) failed: %d\n",
            status);
    }
}

/* ---------- back-channel REFER that drives the display ---------------- */

/*
 * Build & send an out-of-dialog REFER back to the phone whose body is a
 * <statuslineupdatereq>.
 *
 *   Request-URI   = phone's Contact URI (from incoming REFER)
 *   From          = incoming REFER's To URI + fresh local tag
 *   To            = incoming REFER's From URI (no tag — this is a brand new
 *                   out-of-dialog transaction)
 *   Call-ID       = auto
 *   Content-Type  = application/x-cisco-remotecc-request+xml
 *   Refer-To      = cid:<contentid>
 *   Require       = norefersub
 *   Expires       = 0
 *
 * dialog_* are the call's dialog coordinates (same as what we parsed from
 * the incoming REFER body); we swap localtag/remotetag in the OUTGOING body
 * because the tags must be written from Asterisk's perspective.
 */
static void cisco_rec_send_status_refer(pjsip_rx_data *rdata,
    const char *dialog_callid,
    const char *dialog_phone_tag,
    const char *dialog_asterisk_tag,
    const char *status_text,
    int display_timeout)
{
    /*
     * PJSIP_REFER_METHOD is declared in pjsip-simple (the event-subscription
     * framework), which external Asterisk modules don't necessarily link
     * against.  The portable way is PJSIP_OTHER_METHOD + the name string —
     * pjsip matches methods by name first, id second, so this is fully
     * equivalent on the wire.
     */
    static const pjsip_method refer_method = {
        PJSIP_OTHER_METHOD,
        { "REFER", 5 }
    };
    pjsip_endpoint *endpt = ast_sip_get_pjsip_endpoint();
    pjsip_msg *msg = rdata->msg_info.msg;
    pjsip_from_hdr *refer_from = rdata->msg_info.from;
    pjsip_to_hdr   *refer_to   = rdata->msg_info.to;
    pjsip_contact_hdr *refer_contact;
    pjsip_transport *tp = rdata->tp_info.transport;
    pjsip_tx_data *tdata;
    pj_status_t status;
    pj_str_t target_s, from_s, to_s, contact_s;
    pj_str_t hname, hval;
    char target_buf[256], from_buf[512], to_buf[512], contact_buf[256];
    char body_buf[2048];
    char cid_buf[128], referto_buf[160], contentid_buf[160];
    char tag_buf[64];
    int n;

    if (!refer_from || !refer_to || !tp) {
        ast_log(LOG_WARNING,
            "CiscoRecord: status REFER missing required headers\n");
        return;
    }

    refer_contact = (pjsip_contact_hdr *)pjsip_msg_find_hdr(msg,
        PJSIP_H_CONTACT, NULL);

    n = pjsip_uri_print(PJSIP_URI_IN_REQ_URI,
        refer_contact ? refer_contact->uri
                      : pjsip_uri_get_uri(refer_from->uri),
        target_buf, sizeof(target_buf) - 1);
    if (n <= 0) return;
    target_buf[n] = '\0';
    target_s.ptr = target_buf; target_s.slen = n;

    /* From (ours) = REFER's To URI.  We patch a fresh tag onto the parsed
     * header struct after request creation — same reason as in the NOTIFY
     * builder (pjsip_endpt_create_request parses the URI string as a
     * name-addr and rejects ";tag=" parameters). */
    n = pjsip_uri_print(PJSIP_URI_IN_FROMTO_HDR, refer_to->uri,
        from_buf, sizeof(from_buf) - 1);
    if (n <= 0) return;
    from_buf[n] = '\0';
    from_s.ptr = from_buf; from_s.slen = n;

    n = pjsip_uri_print(PJSIP_URI_IN_FROMTO_HDR, refer_from->uri,
        to_buf, sizeof(to_buf) - 1);
    if (n <= 0) return;
    to_buf[n] = '\0';
    to_s.ptr = to_buf; to_s.slen = n;

    n = snprintf(contact_buf, sizeof(contact_buf),
        "<sip:%.*s:%d>",
        (int)tp->local_name.host.slen, tp->local_name.host.ptr,
        tp->local_name.port);
    contact_s.ptr = contact_buf; contact_s.slen = n;

    status = pjsip_endpt_create_request(endpt, &refer_method,
        &target_s, &from_s, &to_s, &contact_s, NULL /* auto Call-ID */,
        -1 /* auto CSeq */, NULL, &tdata);
    if (status != PJ_SUCCESS) {
        ast_log(LOG_WARNING,
            "CiscoRecord: pjsip_endpt_create_request(REFER) failed: %d\n", status);
        return;
    }

    /* Patch a fresh From tag onto the parsed header struct. */
    snprintf(tag_buf, sizeof(tag_buf), "as%lx%lx",
        (unsigned long)ast_random(), (unsigned long)ast_tvnow().tv_usec);
    {
        pjsip_from_hdr *f = (pjsip_from_hdr *)pjsip_msg_find_hdr(tdata->msg,
            PJSIP_H_FROM, NULL);
        if (f) {
            pj_str_t tag_s = { tag_buf, (pj_ssize_t)strlen(tag_buf) };
            pj_strdup(tdata->pool, &f->tag, &tag_s);
        }
    }

    /* Build a content-id value we'll use both as Refer-To ("cid:xxx") and
     * as the Content-Id header.  This is the Cisco-proprietary pattern in
     * CUCM: the REFER "refers to" its own body via cid. */
    snprintf(cid_buf, sizeof(cid_buf), "as%lx@%.*s",
        (unsigned long)ast_random(),
        (int)tp->local_name.host.slen, tp->local_name.host.ptr);
    snprintf(referto_buf,   sizeof(referto_buf),   "cid:%s", cid_buf);
    snprintf(contentid_buf, sizeof(contentid_buf), "<%s>",   cid_buf);

    hname = pj_str("Refer-To");
    hval.ptr = referto_buf; hval.slen = (pj_ssize_t)strlen(referto_buf);
    pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr *)
        pjsip_generic_string_hdr_create(tdata->pool, &hname, &hval));

    hname = pj_str("Referred-By");
    hval = from_s;
    pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr *)
        pjsip_generic_string_hdr_create(tdata->pool, &hname, &hval));

    hname = pj_str("Require");
    hval  = pj_str("norefersub");
    pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr *)
        pjsip_generic_string_hdr_create(tdata->pool, &hname, &hval));

    {
        pjsip_expires_hdr *exp = pjsip_expires_hdr_create(tdata->pool, 0);
        pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr *)exp);
    }

    hname = pj_str("Content-Id");
    hval.ptr = contentid_buf; hval.slen = (pj_ssize_t)strlen(contentid_buf);
    pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr *)
        pjsip_generic_string_hdr_create(tdata->pool, &hname, &hval));

    hname = pj_str("Content-Disposition");
    hval  = pj_str("session;handling=required");
    pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr *)
        pjsip_generic_string_hdr_create(tdata->pool, &hname, &hval));

    /*
     * Body: statuslineupdatereq.  The dialog-id tags are written from
     * Asterisk's perspective, which is the opposite of what was in the
     * incoming REFER's body:
     *   outgoing <localtag>  = Asterisk's tag = incoming <remotetag>
     *   outgoing <remotetag> = phone's tag    = incoming <localtag>
     */
    n = snprintf(body_buf, sizeof(body_buf),
        "<?xml version=\"1.0\" encoding=\"iso-8859-1\"?>\n"
        "<x-cisco-remotecc-request>\n"
        "<statuslineupdatereq>\n"
        "<action>notify_display</action>\n"
        "<dialogid>\n"
        "<callid>%s</callid>\n"
        "<localtag>%s</localtag>\n"
        "<remotetag>%s</remotetag>\n"
        "</dialogid>\n"
        "<statustext>%s</statustext>\n"
        "<displaytimeout>%d</displaytimeout>\n"
        "<priority>1</priority>\n"
        "</statuslineupdatereq>\n"
        "</x-cisco-remotecc-request>\n",
        dialog_callid,
        dialog_asterisk_tag, /* Asterisk's local */
        dialog_phone_tag,    /* phone's remote   */
        status_text,
        display_timeout);

    {
        pj_str_t ct_type    = pj_str("application");
        pj_str_t ct_subtype = pj_str("x-cisco-remotecc-request+xml");
        pj_str_t body_str   = { body_buf, (pj_ssize_t)n };
        tdata->msg->body = pjsip_msg_body_create(tdata->pool,
            &ct_type, &ct_subtype, &body_str);
    }

    status = pjsip_endpt_send_request_stateless(endpt, tdata, NULL, NULL);
    if (status != PJ_SUCCESS) {
        ast_log(LOG_WARNING,
            "CiscoRecord: pjsip_endpt_send_request_stateless(REFER) failed: %d\n",
            status);
    } else {
        ast_log(LOG_NOTICE,
            "CiscoRecord: sent statuslineupdatereq REFER ('%s')\n",
            status_text);
    }
}

/* ---------- MixMonitor driver ----------------------------------------- */

struct rec_task {
    char chan_name[AST_CHANNEL_NAME];
    int  start;        /* 1 = StartRecording, 0 = StopRecording */
    char filename[256];
};

static void *cc_record_thread(void *data)
{
    struct rec_task *t = data;
    struct ast_channel *chan;
    struct ast_app *app;

    /* Let the 202 leave the wire before we attach the audiohook. */
    usleep(100000);

    chan = ast_channel_get_by_name(t->chan_name);
    if (!chan) {
        ast_log(LOG_WARNING,
            "CiscoRecord: channel '%s' gone before MixMonitor could start\n",
            t->chan_name);
        ast_free(t);
        return NULL;
    }

    if (t->start) {
        app = pbx_findapp("MixMonitor");
        if (!app) {
            ast_log(LOG_WARNING,
                "CiscoRecord: MixMonitor application not found "
                "(app_mixmonitor.so not loaded?)\n");
        } else {
            ast_log(LOG_NOTICE,
                "CiscoRecord: starting MixMonitor on %s -> %s\n",
                t->chan_name, t->filename);
            /* No 'b' flag so we also record while the call is not yet
             * bridged (holds, music-on-hold).  Use plain wav. */
            pbx_exec(chan, app, t->filename);
        }
    } else {
        app = pbx_findapp("StopMixMonitor");
        if (!app) {
            ast_log(LOG_WARNING,
                "CiscoRecord: StopMixMonitor not found\n");
        } else {
            ast_log(LOG_NOTICE,
                "CiscoRecord: stopping MixMonitor on %s\n", t->chan_name);
            pbx_exec(chan, app, "");
        }
    }

    ast_channel_unref(chan);
    ast_free(t);
    return NULL;
}

/* ---------- PJSIP receive callback ------------------------------------ */

static pj_bool_t cisco_rec_on_rx_request(pjsip_rx_data *rdata)
{
    pjsip_msg *msg = rdata->msg_info.msg;
    pjsip_tx_data *resp;
    char body[8192], event[64], section[2048];
    char dlg_callid[256], dlg_ltag[128], dlg_rtag[128];
    const char *p, *q;
    size_t slen;
    int blen;
    struct ast_channel *chan;
    struct rec_task *task;
    pthread_attr_t attr;
    pthread_t thr;
    int is_start;

    if (pjsip_method_cmp(&msg->line.req.method, &pjsip_refer_method) != 0)
        return PJ_FALSE;

    if (!msg->body || !msg->body->data || !msg->body->len)
        return PJ_FALSE;

    if (pj_stricmp2(&msg->body->content_type.type,    "application") != 0 ||
        pj_stricmp2(&msg->body->content_type.subtype, "x-cisco-remotecc-request+xml") != 0)
        return PJ_FALSE;

    blen = (int)msg->body->len < (int)(sizeof(body) - 1)
           ? (int)msg->body->len : (int)(sizeof(body) - 1);
    memcpy(body, msg->body->data, blen);
    body[blen] = '\0';

    if (xml_get(body, "softkeyevent", event, sizeof(event)) != 0)
        return PJ_FALSE;

    if (!strcasecmp(event, "StartRecording")) {
        is_start = 1;
    } else if (!strcasecmp(event, "StopRecording")) {
        is_start = 0;
    } else {
        /* Not ours — let res_pjsip_cisco_conference or friends see it. */
        return PJ_FALSE;
    }

    /* Parse <dialogid> — the call we're recording. */
    p = strstr(body, "<dialogid>");
    q = strstr(body, "</dialogid>");
    if (!p || !q) goto malformed;
    slen = (size_t)(q - p) + strlen("</dialogid>");
    if (slen >= sizeof(section)) slen = sizeof(section) - 1;
    memcpy(section, p, slen); section[slen] = '\0';

    if (xml_get(section, "callid",    dlg_callid, sizeof(dlg_callid)) ||
        xml_get(section, "localtag",  dlg_ltag,   sizeof(dlg_ltag))   ||
        xml_get(section, "remotetag", dlg_rtag,   sizeof(dlg_rtag)))
        goto malformed;

    /*
     * Toggle: the phone's softkey doesn't advance to "Stop", so every
     * press sends another StartRecording.  We turn the second
     * StartRecording for the same dialog call-id into a Stop.  An
     * explicit StopRecording (rare) just falls straight through.
     */
    if (is_start && rec_is_active(dlg_callid)) {
        ast_log(LOG_NOTICE,
            "CiscoRecord: StartRecording REFER for call-id='%s' "
            "but recording already active — treating as STOP\n",
            dlg_callid);
        is_start = 0;
    }

    ast_log(LOG_NOTICE,
        "CiscoRecord: %s REFER — call-id='%s'\n",
        is_start ? "StartRecording" : "StopRecording", dlg_callid);

    chan = channel_for_dialog(dlg_callid, dlg_ltag, dlg_rtag);
    /* No channel?  We still pretend recording worked — the phone UI gets
     * the display update and we log.  (User request: never look like a
     * failure on the phone.) */
    if (!chan) {
        ast_log(LOG_WARNING,
            "CiscoRecord: no channel for call-id='%s' — will still "
            "send display update to phone\n", dlg_callid);
    }

    /* ---- send 202 Accepted ----------------------------------------- */
    char local_tag_buf[128] = "";
    pj_str_t local_tag = { NULL, 0 };

    if (pjsip_endpt_create_response(ast_sip_get_pjsip_endpoint(),
            rdata, 202, NULL, &resp) == PJ_SUCCESS) {
        pjsip_to_hdr *to_h = (pjsip_to_hdr *)pjsip_msg_find_hdr(
            resp->msg, PJSIP_H_TO, NULL);
        if (to_h && to_h->tag.slen > 0) {
            int tlen = (int)to_h->tag.slen;
            if (tlen > (int)sizeof(local_tag_buf) - 1)
                tlen = sizeof(local_tag_buf) - 1;
            memcpy(local_tag_buf, to_h->tag.ptr, tlen);
            local_tag_buf[tlen] = '\0';
            local_tag.ptr = local_tag_buf;
            local_tag.slen = tlen;
        }
        pjsip_endpt_send_response2(ast_sip_get_pjsip_endpoint(),
            rdata, resp, NULL, NULL);
    } else {
        ast_log(LOG_ERROR, "CiscoRecord: could not create 202 response\n");
    }

    /* Terminate the implicit subscription so the Record softkey unlocks. */
    cisco_rec_send_refer_notify(rdata, &local_tag);

    /* ---- display update REFER to phone ---------------------------- */
    /* is_start → "Recording" banner for 10 s, auto-refreshed by phone.
     * Phone's dictionary has no localized entry for this free-form text,
     * it simply shows it verbatim on the status line.
     *
     * Stop → "Recording stopped" for 5 s, so the user gets an explicit
     * confirmation that the press toggled recording off (otherwise the
     * banner would just silently disappear and it's easy to doubt
     * whether the press registered).  The phone clears the banner
     * automatically when the timeout expires.
     */
    cisco_rec_send_status_refer(rdata, dlg_callid, dlg_ltag, dlg_rtag,
        is_start ? "Recording" : "Recording stopped",
        is_start ? 10 : 5);

    /* ---- drive MixMonitor on the channel -------------------------- */
    if (chan) {
        task = ast_calloc(1, sizeof(*task));
        if (!task) {
            ast_channel_unref(chan);
            return PJ_TRUE;
        }
        ast_copy_string(task->chan_name, ast_channel_name(chan),
            sizeof(task->chan_name));
        task->start = is_start;
        if (is_start) {
            /* Sanitise dlg_callid for use in a filename (strip '@' and such). */
            char safe[128];
            size_t i, j = 0;
            for (i = 0; dlg_callid[i] && j < sizeof(safe) - 1; i++) {
                char c = dlg_callid[i];
                if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9') || c == '-' || c == '_')
                    safe[j++] = c;
                else
                    safe[j++] = '_';
            }
            safe[j] = '\0';
            snprintf(task->filename, sizeof(task->filename),
                "cisco-%s-%ld.wav", safe, (long)ast_tvnow().tv_sec);
        }
        ast_channel_unref(chan);

        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&thr, &attr, cc_record_thread, task) != 0) {
            ast_log(LOG_ERROR, "CiscoRecord: pthread_create failed\n");
            ast_free(task);
        } else {
            /*
             * Only update the toggle set when the worker was actually
             * scheduled.  rec_add is idempotent; rec_remove on a missing
             * entry is a no-op.  (We don't try to rollback if MixMonitor
             * itself fails inside the thread — the user-visible UI is
             * still "Recording" per design.)
             */
            if (is_start)
                rec_add(dlg_callid);
            else
                rec_remove(dlg_callid);
        }
        pthread_attr_destroy(&attr);
    } else {
        /* No channel found at all — keep the set consistent with what
         * the phone believes.  If this was supposed to be a Start it
         * would have been toggled to Stop above (because a prior Start
         * put us in the set); treat the else branch as "we're done
         * with this call-id". */
        if (!is_start)
            rec_remove(dlg_callid);
    }

    return PJ_TRUE;

malformed:
    ast_log(LOG_WARNING, "CiscoRecord: malformed x-cisco-remotecc body\n");
    if (pjsip_endpt_create_response(ast_sip_get_pjsip_endpoint(),
            rdata, 400, NULL, &resp) == PJ_SUCCESS)
        pjsip_endpt_send_response2(ast_sip_get_pjsip_endpoint(),
            rdata, resp, NULL, NULL);
    return PJ_TRUE;
}

/* ---------- module registration --------------------------------------- */

static pjsip_module cisco_rec_pjsip_module = {
    .name     = { "mod-cisco-record", 17 },
    /*
     * Lower = higher priority.  res_pjsip_cisco_conference sits at
     * APPLICATION-1 (31) and consumes *all* x-cisco-remotecc REFERs —
     * silently 200-OK'ing any softkey it doesn't recognise (including
     * StartRecording / StopRecording).  We therefore register at
     * APPLICATION-2 (30) so we see the REFER first; if the event isn't
     * ours we return PJ_FALSE and the conference module gets it next.
     */
    .priority = PJSIP_MOD_PRIORITY_APPLICATION - 2,
    .on_rx_request = cisco_rec_on_rx_request,
};

static int load_module(void)
{
    if (ast_sip_register_service(&cisco_rec_pjsip_module)) {
        ast_log(LOG_ERROR, "CiscoRecord: failed to register PJSIP service\n");
        return AST_MODULE_LOAD_DECLINE;
    }
    ast_log(LOG_NOTICE, "CiscoRecord: Cisco record module loaded\n");
    return AST_MODULE_LOAD_SUCCESS;
}

static int unload_module(void)
{
    ast_sip_unregister_service(&cisco_rec_pjsip_module);
    rec_clear_all();
    return 0;
}

AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_DEFAULT,
    "Cisco x-cisco-remotecc Record Handler",
    .support_level = AST_MODULE_SUPPORT_EXTENDED,
    .load   = load_module,
    .unload = unload_module,
    .requires = "res_pjsip,res_pjsip_session",
);
