/* Copyright (C) 2024 Timon Schneider info@timon-schneider.com
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * res_pjsip_cisco_record.c
 *
 * Intercepts Cisco x-cisco-remotecc StartRecording / StopRecording REFER
 * requests (sent when the user presses the Record softkey on a CP-8xxx)
 * and reproduces the exact SIP dance that a real CUCM14 performs so that
 * the phone's own built-in softkey state machine flips to "Stop
 * Recording" while recording is active.
 *
 * Wire sequence (matches a successful Wireshark capture against CUCM14):
 *
 *   On StartRecording:
 *     1.  PBX -> phone: 202 Accepted to the REFER.
 *         (No NOTIFY: the REFER sets "Require: norefersub" so no
 *          implicit subscription is created and none is needed.)
 *     2.  PBX -> phone: two fresh out-of-main-dialog INVITEs back to
 *         the phone's Contact URI, each carrying:
 *
 *           Call-Info:  <urn:x-cisco-remotecc:callinfo>; isVoip; \
 *                       record-invoker=user
 *           Join:       <main-call-id>;from-tag=<phone-tag>;\
 *                       to-tag=<asterisk-tag>
 *           Content-Disposition: session;handling=required
 *           SDP:        a=label:X-relay-nearend   (1st leg)
 *                       a=label:X-relay-farend    (2nd leg)
 *                       + opus/48000/2 + ephemeral local UDP port
 *
 *         Seeing these two relay dialogs accepted is what drives the
 *         phone's softkey state machine to display "Stop Recording" -
 *         no proprietary statuslineupdatereq or other display hack is
 *         involved.
 *     3.  Recording to disk is driven by MixMonitor on the Asterisk
 *         channel that is bridged to the main call, producing
 *           /var/spool/asterisk/monitor/cisco-<call-id>-<epoch>.wav
 *         exactly as in earlier revisions of this module.
 *
 *   On StopRecording (now really sent by the phone because the softkey
 *   did flip):
 *     1.  PBX -> phone: 202 Accepted.
 *     2.  PBX -> phone: BYE on each of the two relay dialogs.
 *     3.  StopMixMonitor on the bridged channel.
 *
 * We never consume the RTP the phone streams on the two relay legs;
 * the advertised SDP ports are backed by UDP sockets we bind only so
 * the kernel silently drops the packets, without ICMP unreachable
 * bouncing back at the phone.  Actual audio capture continues to go
 * through MixMonitor on the bridged channel.
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
#include <pjmedia.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

/* ---------- per-main-call relay-session table ------------------------ *
 *
 * For every call that is currently being recorded we keep a single
 * entry keyed by the main Cisco dialog's Call-ID.  It owns:
 *
 *   - the identifying tags (for logging)
 *   - the bridged Asterisk channel's name (so StopRecording can drive
 *     StopMixMonitor without having to re-resolve the dialog, by which
 *     time the channel may already be tearing down)
 *   - the two relay-leg pjsip_inv_session pointers (so StopRecording
 *     can BYE them via pjsip_inv_end_session); each is held with
 *     pjsip_inv_add_ref and released with pjsip_inv_dec_ref
 *   - the two UDP sockets bound for the advertised SDP ports.  We
 *     never read from them; they are closed when the entry is torn
 *     down.
 */
struct relay_sess {
    char main_callid[256];
    char main_localtag[128];    /* phone's own tag (= XML <localtag>) */
    char main_remotetag[128];   /* Asterisk's tag (= XML <remotetag>) */
    char chan_name[AST_CHANNEL_NAME];
    pjsip_inv_session *inv_nearend;
    pjsip_inv_session *inv_farend;
    int udp_fd_nearend;
    int udp_fd_farend;
    AST_LIST_ENTRY(relay_sess) list;
};

static AST_LIST_HEAD_STATIC(relay_sessions, relay_sess);

/* caller must hold the list lock */
static struct relay_sess *relay_find_locked(const char *call_id)
{
    struct relay_sess *e;
    AST_LIST_TRAVERSE(&relay_sessions, e, list) {
        if (!strcmp(e->main_callid, call_id))
            return e;
    }
    return NULL;
}

/* caller must hold the list lock */
static struct relay_sess *relay_add_locked(const char *call_id,
    const char *phone_tag, const char *asterisk_tag, const char *chan_name)
{
    struct relay_sess *e = relay_find_locked(call_id);
    if (e)
        return e;
    e = ast_calloc(1, sizeof(*e));
    if (!e)
        return NULL;
    ast_copy_string(e->main_callid, call_id, sizeof(e->main_callid));
    ast_copy_string(e->main_localtag, phone_tag, sizeof(e->main_localtag));
    ast_copy_string(e->main_remotetag, asterisk_tag,
        sizeof(e->main_remotetag));
    if (chan_name)
        ast_copy_string(e->chan_name, chan_name, sizeof(e->chan_name));
    e->udp_fd_nearend = -1;
    e->udp_fd_farend = -1;
    AST_LIST_INSERT_HEAD(&relay_sessions, e, list);
    return e;
}

/* ---------- tiny XML helpers (same as previous revisions) ------------- */

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
        ast_log(LOG_WARNING,
            "CiscoRecord: dialog not found for call-id='%s'\n", call_id);
        return NULL;
    }

    session = ast_sip_dialog_get_session(dlg);
    pjsip_dlg_dec_lock(dlg);

    if (!session) {
        ast_log(LOG_WARNING,
            "CiscoRecord: no session for call-id='%s'\n", call_id);
        return NULL;
    }

    if (session->channel)
        chan = ast_channel_ref(session->channel);
    ao2_ref(session, -1);

    if (!chan)
        ast_log(LOG_WARNING,
            "CiscoRecord: no channel in session for call-id='%s'\n", call_id);

    return chan;
}

/*
 * Bind a UDP socket to 0.0.0.0:0 and return the ephemeral port.  The
 * socket is deliberately never read from.  Its sole purpose is to keep
 * a kernel RX hook alive on the advertised SDP port so RTP arriving
 * from the phone is silently dropped rather than generating ICMP port
 * unreachable replies.
 */
static int bind_ephemeral_udp(int *port_out)
{
    struct sockaddr_in sa;
    socklen_t slen = sizeof(sa);
    int fd;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    sa.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd);
        return -1;
    }
    if (getsockname(fd, (struct sockaddr *)&sa, &slen) != 0) {
        close(fd);
        return -1;
    }
    *port_out = (int)ntohs(sa.sin_port);
    return fd;
}

/* ---------- relay-leg INVITE builder --------------------------------- *
 *
 * Open one relay-leg INVITE UAC dialog back to the phone.  Returns the
 * pjsip_inv_session * with one additional reference held on behalf of
 * the caller (so the caller may stash the pointer and later
 * pjsip_inv_end_session + pjsip_inv_dec_ref it); returns NULL on
 * failure, in which case the bound UDP fd has been closed too.
 *
 *   Request-URI  = phone's Contact URI (from incoming REFER)
 *   From         = incoming REFER's To URI + fresh local tag (pjsip
 *                  auto-generates the tag for UAC dialogs)
 *   To           = incoming REFER's From URI (no tag - brand-new dialog)
 *   Contact      = <sip:<ast-host>:<ast-port>>
 *   Call-Info    = <urn:x-cisco-remotecc:callinfo>; isVoip; \
 *                  record-invoker=user
 *   Join         = <main-callid>;from-tag=<phone-tag>;to-tag=<ast-tag>
 *   Content-Disposition = session;handling=required
 *   Body         = application/sdp, opus/48000/2 offer, a=sendrecv,
 *                  labelled X-relay-nearend or X-relay-farend
 */
static pjsip_inv_session *cisco_rec_send_relay_invite(
    pjsip_rx_data *rdata,
    const char *main_callid,
    const char *phone_localtag,
    const char *asterisk_tag,
    const char *label,
    int *udp_fd_out)
{
    pjsip_msg *msg = rdata->msg_info.msg;
    pjsip_from_hdr *refer_from = rdata->msg_info.from;
    pjsip_to_hdr   *refer_to   = rdata->msg_info.to;
    pjsip_contact_hdr *refer_contact;
    pjsip_transport *tp = rdata->tp_info.transport;
    pjsip_dialog *dlg = NULL;
    pjsip_inv_session *inv = NULL;
    pjsip_tx_data *tdata = NULL;
    pjmedia_sdp_session *sdp = NULL;
    pj_status_t status;
    pj_str_t target_s, local_uri_s, remote_uri_s, contact_s;
    pj_str_t hname, hval;
    char target_buf[256], local_uri_buf[512], remote_uri_buf[512];
    char contact_buf[256];
    char sdp_buf[1024];
    char callinfo_buf[256], join_buf[640];
    int udp_port = 0, udp_fd = -1;
    int inv_ref_held = 0;
    int n;

    if (!refer_from || !refer_to || !tp) {
        ast_log(LOG_WARNING,
            "CiscoRecord: missing headers for relay INVITE\n");
        return NULL;
    }

    refer_contact = (pjsip_contact_hdr *)pjsip_msg_find_hdr(msg,
        PJSIP_H_CONTACT, NULL);
    if (!refer_contact || !refer_contact->uri) {
        ast_log(LOG_WARNING,
            "CiscoRecord: REFER has no Contact, cannot open relay leg\n");
        return NULL;
    }

    udp_fd = bind_ephemeral_udp(&udp_port);
    if (udp_fd < 0) {
        ast_log(LOG_WARNING,
            "CiscoRecord: failed to bind ephemeral UDP socket for relay\n");
        return NULL;
    }

    n = pjsip_uri_print(PJSIP_URI_IN_REQ_URI, refer_contact->uri,
        target_buf, sizeof(target_buf) - 1);
    if (n <= 0) goto fail;
    target_buf[n] = '\0';
    target_s.ptr = target_buf; target_s.slen = n;

    n = pjsip_uri_print(PJSIP_URI_IN_FROMTO_HDR, refer_to->uri,
        local_uri_buf, sizeof(local_uri_buf) - 1);
    if (n <= 0) goto fail;
    local_uri_buf[n] = '\0';
    local_uri_s.ptr = local_uri_buf; local_uri_s.slen = n;

    n = pjsip_uri_print(PJSIP_URI_IN_FROMTO_HDR, refer_from->uri,
        remote_uri_buf, sizeof(remote_uri_buf) - 1);
    if (n <= 0) goto fail;
    remote_uri_buf[n] = '\0';
    remote_uri_s.ptr = remote_uri_buf; remote_uri_s.slen = n;

    n = snprintf(contact_buf, sizeof(contact_buf),
        "<sip:%.*s:%d>",
        (int)tp->local_name.host.slen, tp->local_name.host.ptr,
        tp->local_name.port);
    contact_s.ptr = contact_buf; contact_s.slen = n;

    status = pjsip_dlg_create_uac(pjsip_ua_instance(),
        &local_uri_s, &contact_s, &remote_uri_s, &target_s, &dlg);
    if (status != PJ_SUCCESS) {
        ast_log(LOG_WARNING,
            "CiscoRecord: pjsip_dlg_create_uac failed: %d\n", status);
        goto fail;
    }

    n = snprintf(sdp_buf, sizeof(sdp_buf),
        "v=0\r\n"
        "o=Asterisk %ld 1 IN IP4 %.*s\r\n"
        "s=SIP Call\r\n"
        "c=IN IP4 %.*s\r\n"
        "t=0 0\r\n"
        "m=audio %d RTP/AVP 114\r\n"
        "a=label:%s\r\n"
        "a=rtpmap:114 opus/48000/2\r\n"
        "a=fmtp:114 maxplaybackrate=16000;sprop-maxcapturerate=16000;"
        "maxaveragebitrate=64000;stereo=0;sprop-stereo=0;usedtx=0\r\n"
        "a=sendrecv\r\n",
        (long)ast_tvnow().tv_sec,
        (int)tp->local_name.host.slen, tp->local_name.host.ptr,
        (int)tp->local_name.host.slen, tp->local_name.host.ptr,
        udp_port,
        label);
    if (n <= 0 || n >= (int)sizeof(sdp_buf)) {
        ast_log(LOG_WARNING, "CiscoRecord: SDP buffer too small\n");
        goto fail_after_dlg;
    }

    status = pjmedia_sdp_parse(dlg->pool, sdp_buf, n, &sdp);
    if (status != PJ_SUCCESS) {
        ast_log(LOG_WARNING,
            "CiscoRecord: pjmedia_sdp_parse failed: %d\n", status);
        goto fail_after_dlg;
    }

    status = pjsip_inv_create_uac(dlg, sdp, 0, &inv);
    if (status != PJ_SUCCESS) {
        ast_log(LOG_WARNING,
            "CiscoRecord: pjsip_inv_create_uac failed: %d\n", status);
        goto fail_after_dlg;
    }

    /*
     * Bump the INV refcount so that it remains valid both across the
     * rest of this function (if the far end somehow terminated it
     * synchronously inside pjsip_inv_send_msg) and across the hand-off
     * back to the caller who will later pjsip_inv_end_session +
     * pjsip_inv_dec_ref.  We do NOT register our own INV callback --
     * res_pjsip_session has already called pjsip_inv_usage_init once
     * per endpoint, which is the only time that's allowed.  The INV
     * layer handles auto-ACK on 2xx internally regardless of whether
     * the registered callback touches our INV.
     */
    pjsip_inv_add_ref(inv);
    inv_ref_held = 1;

    status = pjsip_inv_invite(inv, &tdata);
    if (status != PJ_SUCCESS) {
        ast_log(LOG_WARNING,
            "CiscoRecord: pjsip_inv_invite failed: %d\n", status);
        pjsip_inv_terminate(inv, 500, PJ_FALSE);
        goto fail_after_inv;
    }

    n = snprintf(callinfo_buf, sizeof(callinfo_buf),
        "<urn:x-cisco-remotecc:callinfo>; isVoip; record-invoker=user");
    hname = pj_str("Call-Info");
    hval.ptr = callinfo_buf; hval.slen = n;
    pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr *)
        pjsip_generic_string_hdr_create(tdata->pool, &hname, &hval));

    n = snprintf(join_buf, sizeof(join_buf),
        "%s;from-tag=%s;to-tag=%s",
        main_callid, phone_localtag, asterisk_tag);
    hname = pj_str("Join");
    hval.ptr = join_buf; hval.slen = n;
    pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr *)
        pjsip_generic_string_hdr_create(tdata->pool, &hname, &hval));

    hname = pj_str("Content-Disposition");
    hval  = pj_str("session;handling=required");
    pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr *)
        pjsip_generic_string_hdr_create(tdata->pool, &hname, &hval));

    status = pjsip_inv_send_msg(inv, tdata);
    if (status != PJ_SUCCESS) {
        ast_log(LOG_WARNING,
            "CiscoRecord: pjsip_inv_send_msg(INVITE) failed: %d\n", status);
        /* pjsip_inv_send_msg cleans tdata up internally on failure;
         * terminate to release the inv's creation ref too so our
         * subsequent pjsip_inv_dec_ref finishes destruction. */
        pjsip_inv_terminate(inv, 500, PJ_FALSE);
        goto fail_after_inv;
    }

    *udp_fd_out = udp_fd;
    ast_log(LOG_NOTICE,
        "CiscoRecord: sent relay INVITE label=%s local-port=%d\n",
        label, udp_port);
    return inv;

fail_after_inv:
    if (inv_ref_held) {
        pjsip_inv_dec_ref(inv);
        inv_ref_held = 0;
    }
    inv = NULL;
    /* pjsip_inv_terminate (above) disassociates us from the dialog; the
     * dialog's own usage release + our dec_ref cause destruction. */
    goto fail;

fail_after_dlg:
    if (dlg)
        pjsip_dlg_terminate(dlg);
fail:
    if (udp_fd >= 0) close(udp_fd);
    return NULL;
}

/* ---------- BYE an inv ------------------------------------------------ */

static void send_bye_inv(pjsip_inv_session *inv)
{
    pjsip_tx_data *tdata = NULL;
    pj_status_t status;

    if (!inv)
        return;

    status = pjsip_inv_end_session(inv, 200, NULL, &tdata);
    if (status == PJ_SUCCESS && tdata) {
        status = pjsip_inv_send_msg(inv, tdata);
        if (status != PJ_SUCCESS) {
            ast_log(LOG_WARNING,
                "CiscoRecord: pjsip_inv_send_msg(BYE) failed: %d\n",
                status);
        }
    }
}

/* ---------- MixMonitor driver ----------------------------------------- */

struct rec_task {
    char chan_name[AST_CHANNEL_NAME];
    int  start;         /* 1 = MixMonitor, 0 = StopMixMonitor */
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
            "CiscoRecord: channel '%s' gone before (Stop)MixMonitor\n",
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

static int spawn_mixmonitor_task(const char *chan_name, int start,
    const char *callid_for_filename)
{
    struct rec_task *task;
    pthread_attr_t attr;
    pthread_t thr;

    task = ast_calloc(1, sizeof(*task));
    if (!task)
        return -1;
    ast_copy_string(task->chan_name, chan_name, sizeof(task->chan_name));
    task->start = start;

    if (start && callid_for_filename) {
        char safe[128];
        size_t i, j = 0;
        for (i = 0; callid_for_filename[i] && j < sizeof(safe) - 1; i++) {
            char c = callid_for_filename[i];
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

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&thr, &attr, cc_record_thread, task) != 0) {
        ast_log(LOG_ERROR, "CiscoRecord: pthread_create failed\n");
        ast_free(task);
        pthread_attr_destroy(&attr);
        return -1;
    }
    pthread_attr_destroy(&attr);
    return 0;
}

/* ---------- PJSIP receive callback ------------------------------------ */

static pj_bool_t cisco_rec_on_rx_request(pjsip_rx_data *rdata)
{
    pjsip_msg *msg = rdata->msg_info.msg;
    pjsip_endpoint *endpt = ast_sip_get_pjsip_endpoint();
    pjsip_tx_data *resp;
    char body[8192], event[64], section[2048];
    char dlg_callid[256], dlg_ltag[128], dlg_rtag[128];
    const char *p, *q;
    size_t slen;
    int blen;
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
        /* Not ours - let res_pjsip_cisco_conference or friends see it. */
        return PJ_FALSE;
    }

    /* Parse <dialogid> - the call we're (de-)recording. */
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

    ast_log(LOG_NOTICE,
        "CiscoRecord: %s REFER - call-id='%s'\n",
        is_start ? "StartRecording" : "StopRecording", dlg_callid);

    /* Always 202 Accepted the REFER up front (what real CUCM does). */
    if (pjsip_endpt_create_response(endpt, rdata, 202, NULL, &resp)
            == PJ_SUCCESS) {
        pjsip_endpt_send_response2(endpt, rdata, resp, NULL, NULL);
    } else {
        ast_log(LOG_ERROR, "CiscoRecord: could not create 202 response\n");
    }

    if (is_start) {
        struct ast_channel *chan;
        struct relay_sess *e;
        char chan_name[AST_CHANNEL_NAME] = "";
        pjsip_inv_session *inv_near = NULL, *inv_far = NULL;
        int udp_fd_near = -1, udp_fd_far = -1;
        int adopted = 0;

        chan = channel_for_dialog(dlg_callid, dlg_ltag, dlg_rtag);
        if (!chan) {
            ast_log(LOG_WARNING,
                "CiscoRecord: no channel for call-id='%s' - skipping "
                "recording (softkey will not flip)\n", dlg_callid);
            return PJ_TRUE;
        }
        ast_copy_string(chan_name, ast_channel_name(chan), sizeof(chan_name));
        ast_channel_unref(chan);

        AST_LIST_LOCK(&relay_sessions);
        if (relay_find_locked(dlg_callid)) {
            AST_LIST_UNLOCK(&relay_sessions);
            ast_log(LOG_NOTICE,
                "CiscoRecord: call-id='%s' already being recorded - "
                "ignoring duplicate StartRecording\n", dlg_callid);
            return PJ_TRUE;
        }
        e = relay_add_locked(dlg_callid, dlg_ltag, dlg_rtag, chan_name);
        AST_LIST_UNLOCK(&relay_sessions);
        if (!e) {
            ast_log(LOG_ERROR, "CiscoRecord: out of memory\n");
            return PJ_TRUE;
        }

        /* Build & send the two relay legs. */
        inv_near = cisco_rec_send_relay_invite(rdata,
            dlg_callid, dlg_ltag, dlg_rtag,
            "X-relay-nearend", &udp_fd_near);
        inv_far  = cisco_rec_send_relay_invite(rdata,
            dlg_callid, dlg_ltag, dlg_rtag,
            "X-relay-farend", &udp_fd_far);

        /* Transfer the INV refs + UDP fds to the table entry. */
        AST_LIST_LOCK(&relay_sessions);
        e = relay_find_locked(dlg_callid);
        if (e) {
            e->inv_nearend = inv_near;
            e->inv_farend  = inv_far;
            e->udp_fd_nearend = udp_fd_near;
            e->udp_fd_farend  = udp_fd_far;
            adopted = 1;
        }
        AST_LIST_UNLOCK(&relay_sessions);

        if (!adopted) {
            /* Extremely unlikely - entry vanished while we were busy. */
            if (inv_near) { send_bye_inv(inv_near); pjsip_inv_dec_ref(inv_near); }
            if (inv_far)  { send_bye_inv(inv_far);  pjsip_inv_dec_ref(inv_far); }
            if (udp_fd_near >= 0) close(udp_fd_near);
            if (udp_fd_far >= 0) close(udp_fd_far);
        }

        spawn_mixmonitor_task(chan_name, 1, dlg_callid);
    } else {
        struct relay_sess *e;
        char chan_name[AST_CHANNEL_NAME] = "";
        pjsip_inv_session *inv_near = NULL, *inv_far = NULL;
        int udp_fd_near = -1, udp_fd_far = -1;

        AST_LIST_LOCK(&relay_sessions);
        AST_LIST_TRAVERSE_SAFE_BEGIN(&relay_sessions, e, list) {
            if (!strcmp(e->main_callid, dlg_callid)) {
                AST_LIST_REMOVE_CURRENT(list);
                ast_copy_string(chan_name, e->chan_name, sizeof(chan_name));
                inv_near = e->inv_nearend; e->inv_nearend = NULL;
                inv_far  = e->inv_farend;  e->inv_farend  = NULL;
                udp_fd_near = e->udp_fd_nearend; e->udp_fd_nearend = -1;
                udp_fd_far  = e->udp_fd_farend;  e->udp_fd_farend  = -1;
                ast_free(e);
                break;
            }
        }
        AST_LIST_TRAVERSE_SAFE_END;
        AST_LIST_UNLOCK(&relay_sessions);

        if (inv_near) {
            send_bye_inv(inv_near);
            pjsip_inv_dec_ref(inv_near);
        }
        if (inv_far) {
            send_bye_inv(inv_far);
            pjsip_inv_dec_ref(inv_far);
        }
        if (udp_fd_near >= 0) close(udp_fd_near);
        if (udp_fd_far >= 0) close(udp_fd_far);

        if (chan_name[0]) {
            spawn_mixmonitor_task(chan_name, 0, NULL);
        } else {
            ast_log(LOG_NOTICE,
                "CiscoRecord: StopRecording for unknown call-id='%s' "
                "- nothing to tear down\n", dlg_callid);
        }
    }

    return PJ_TRUE;

malformed:
    ast_log(LOG_WARNING, "CiscoRecord: malformed x-cisco-remotecc body\n");
    if (pjsip_endpt_create_response(endpt, rdata, 400, NULL, &resp)
            == PJ_SUCCESS)
        pjsip_endpt_send_response2(endpt, rdata, resp, NULL, NULL);
    return PJ_TRUE;
}

/* ---------- module registration --------------------------------------- */

static pjsip_module cisco_rec_pjsip_module = {
    .name     = { "mod-cisco-record", 17 },
    /*
     * Lower = higher priority.  res_pjsip_cisco_conference sits at
     * APPLICATION-1 (31) and consumes *all* x-cisco-remotecc REFERs -
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
    struct relay_sess *e;

    ast_sip_unregister_service(&cisco_rec_pjsip_module);

    /* Best-effort: BYE every still-live relay leg, close dummy sockets,
     * free the table entries.  The phone will drop its local recording
     * state when the BYEs arrive. */
    AST_LIST_LOCK(&relay_sessions);
    while ((e = AST_LIST_REMOVE_HEAD(&relay_sessions, list))) {
        if (e->inv_nearend) {
            send_bye_inv(e->inv_nearend);
            pjsip_inv_dec_ref(e->inv_nearend);
            e->inv_nearend = NULL;
        }
        if (e->inv_farend) {
            send_bye_inv(e->inv_farend);
            pjsip_inv_dec_ref(e->inv_farend);
            e->inv_farend = NULL;
        }
        if (e->udp_fd_nearend >= 0) close(e->udp_fd_nearend);
        if (e->udp_fd_farend  >= 0) close(e->udp_fd_farend);
        ast_free(e);
    }
    AST_LIST_UNLOCK(&relay_sessions);

    return 0;
}

AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_DEFAULT,
    "Cisco x-cisco-remotecc Record Handler",
    .support_level = AST_MODULE_SUPPORT_EXTENDED,
    .load   = load_module,
    .unload = unload_module,
    .requires = "res_pjsip,res_pjsip_session",
);
