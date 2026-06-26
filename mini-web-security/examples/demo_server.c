#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include "xss_csrf.h"
#include "sqli_inject.h"
#include "owasp_top10.h"
#include "input_validation.h"
#include "auth_session.h"

#define MAX_HEADERS     32
#define MAX_REQ_SIZE    65536
#define MAX_URL_LEN     2048
#define MAX_RESP_LEN    65536

typedef struct {
    char method[16];
    char url[MAX_URL_LEN];
    char host[256];
    char user_agent[512];
    char content_type[128];
    char body[MAX_REQ_SIZE / 2];
    char headers[MAX_HEADERS][1024];
    int  header_count;
    char query_string[4096];
} http_request_t;

typedef struct {
    int     status_code;
    char    content_type[128];
    char    headers[MAX_HEADERS][1024];
    int     header_count;
    char    body[MAX_RESP_LEN];
    size_t  body_len;
} http_response_t;

typedef struct {
    csrf_token_t  csrf_token;
    rate_limiter_t rate_limit;
    owasp_report_t owasp_report;
    csp_policy_t   csp;
    int            request_count;
} server_state_t;

static void parse_request(const char* raw, http_request_t* req) {
    memset(req, 0, sizeof(*req));
    if (!raw) return;
    const char* p = raw;
    sscanf(p, "%15s %2047s", req->method, req->url);
    p = strchr(p, '\n');
    if (!p) return;
    const char* header_end = strstr(raw, "\r\n\r\n");
    if (!header_end) header_end = strstr(raw, "\n\n");
    if (!header_end) return;
    const char* line_start = p + 1;
    char header_block[MAX_REQ_SIZE / 2];
    size_t hb_len = (size_t)(header_end - line_start);
    if (hb_len >= sizeof(header_block)) hb_len = sizeof(header_block) - 1;
    memcpy(header_block, line_start, hb_len);
    header_block[hb_len] = '\0';
    char* line = strtok(header_block, "\r\n");
    while (line && req->header_count < MAX_HEADERS) {
        while (*line == ' ' || *line == '\t') line++;
        strncpy(req->headers[req->header_count], line, 1023);
        req->headers[req->header_count][1023] = '\0';
        if (strncasecmp(line, "Host:", 5) == 0) {
            const char* v = line + 5;
            while (*v == ' ') v++;
            strncpy(req->host, v, 255);
            req->host[255] = '\0';
        }
        if (strncasecmp(line, "User-Agent:", 11) == 0) {
            const char* v = line + 11;
            while (*v == ' ') v++;
            strncpy(req->user_agent, v, 511);
            req->user_agent[511] = '\0';
        }
        req->header_count++;
        line = strtok(NULL, "\r\n");
    }
    const char* qm = strchr(req->url, '?');
    if (qm) {
        strncpy(req->query_string, qm + 1, sizeof(req->query_string) - 1);
        req->query_string[sizeof(req->query_string) - 1] = '\0';
    }
    const char* body_start = header_end + (strstr(raw, "\r\n\r\n") ? 4 : 2);
    if (body_start) {
        strncpy(req->body, body_start, sizeof(req->body) - 1);
        req->body[sizeof(req->body) - 1] = '\0';
    }
}

static void response_init(http_response_t* resp) {
    memset(resp, 0, sizeof(*resp));
    resp->status_code = 200;
    strcpy(resp->content_type, "text/html; charset=utf-8");
    resp->body_len = 0;
    resp->header_count = 0;
}

static void response_add_header(http_response_t* resp, const char* header) {
    if (resp->header_count < MAX_HEADERS) {
        strncpy(resp->headers[resp->header_count], header, 1023);
        resp->headers[resp->header_count][1023] = '\0';
        resp->header_count++;
    }
}

static void response_append_body(http_response_t* resp, const char* text) {
    size_t len = strlen(text);
    if (resp->body_len + len < MAX_RESP_LEN - 1) {
        memcpy(resp->body + resp->body_len, text, len);
        resp->body_len += len;
        resp->body[resp->body_len] = '\0';
    }
}

static void print_response(const http_response_t* resp) {
    printf("HTTP/1.1 %d OK\r\n", resp->status_code);
    printf("Content-Type: %s\r\n", resp->content_type);
    printf("Content-Length: %zu\r\n", resp->body_len);
    for (int i = 0; i < resp->header_count; i++)
        printf("%s\r\n", resp->headers[i]);
    printf("\r\n%s", resp->body);
}

static void handle_security_scan(server_state_t* ss, const http_request_t* req,
                                  http_response_t* resp) {
    response_append_body(resp, "<html><head><title>Security Scan Report</title>");
    response_append_body(resp, "<style>body{font:14px monospace;max-width:800px;margin:20px}");
    response_append_body(resp, ".risk-high{color:red}.risk-med{color:orange}</style>");
    response_append_body(resp, "</head><body>");
    response_append_body(resp, "<h1>mini-web-security Scan Report</h1>\n");

    owasp_report_t scan_report;
    owasp_report_init(&scan_report);
    owasp_scan_url(req->url, &scan_report);
    owasp_scan_headers((const char**)req->headers, req->header_count, &scan_report);

    response_append_body(resp, "<h2>OWASP Top 10 Findings</h2>\n<ul>\n");
    for (int i = 0; i < scan_report.count; i++) {
        char item[1024];
        const char* cls = "risk-med";
        if (scan_report.findings[i].risk == RISK_HIGH || scan_report.findings[i].risk == RISK_CRITICAL)
            cls = "risk-high";
        snprintf(item, sizeof(item),
                 "<li class=\"%s\"><b>%s</b><br>%s<br><em>Fix:</em> %s</li>\n",
                 cls, owasp_category_name(scan_report.findings[i].category),
                 scan_report.findings[i].detail, scan_report.findings[i].remediation);
        response_append_body(resp, item);
    }
    if (scan_report.count == 0)
        response_append_body(resp, "<li>No OWASP Top 10 issues detected</li>\n");
    response_append_body(resp, "</ul>\n");

    response_append_body(resp, "<h2>Input Analysis</h2>\n");
    response_append_body(resp, "<table border='1'><tr><th>Test</th><th>Result</th></tr>\n");

    sqli_detect_result_t sqli_r;
    sqli_detect(req->query_string, &sqli_r);
    char buf[512];
    snprintf(buf, sizeof(buf), "<tr><td>SQL Injection (query)</td><td>%s (risk=%d)</td></tr>\n",
             sqli_type_name(sqli_r.type), sqli_r.risk_score);
    response_append_body(resp, buf);

    dt_result_t dt_r;
    dt_detect(req->url, &dt_r);
    snprintf(buf, sizeof(buf), "<tr><td>Directory Traversal</td><td>%s (depth=%d)</td></tr>\n",
             dt_r.detected ? "DETECTED" : "Clear", dt_r.depth_attempted);
    response_append_body(resp, buf);

    fi_result_t fi_r;
    fi_detect(req->url, &fi_r);
    snprintf(buf, sizeof(buf), "<tr><td>File Inclusion</td><td>%s</td></tr>\n",
             fi_r.detected ? (fi_r.type == FI_LFI ? "LFI" : "RFI") : "Clear");
    response_append_body(resp, buf);

    double_enc_t de;
    double_enc_detect(req->query_string, &de);
    snprintf(buf, sizeof(buf), "<tr><td>Double Encoding</td><td>%s (depth=%d)</td></tr>\n",
             de.detected ? "DETECTED" : "Clear", de.depth);
    response_append_body(resp, buf);

    nosqli_type_t nosql = nosqli_detect(req->query_string);
    snprintf(buf, sizeof(buf), "<tr><td>NoSQL Injection</td><td>%s</td></tr>\n",
             nosql == NOSQLI_NONE ? "Clear" : "DETECTED");
    response_append_body(resp, buf);

    response_append_body(resp, "</table>\n");

    response_append_body(resp, "<h2>Security Headers</h2>\n<ul>\n");
    snprintf(buf, sizeof(buf), "<li>XSS Protection: <code>%s</code></li>\n",
             req->query_string && strstr(req->query_string, "<script>") ? "INJECTION DETECTED" : "OK");
    response_append_body(resp, buf);
    snprintf(buf, sizeof(buf), "<li>Request #%d - Rate limit: %d remaining</li>\n",
             ss->request_count, ratelimit_remaining(&ss->rate_limit));
    response_append_body(resp, buf);
    response_append_body(resp, "</ul>\n");

    response_append_body(resp, "</body></html>");
}

static void handle_login(server_state_t* ss, const http_request_t* req,
                          http_response_t* resp) {
    ss->request_count++;
    if (!ratelimit_check(&ss->rate_limit)) {
        resp->status_code = 429;
        response_append_body(resp, "{\"error\": \"Too many requests. Account temporarily locked.\"}");
        resp->content_type[0] = '\0';
        strcpy(resp->content_type, "application/json");
        return;
    }
    if (req->body && strstr(req->body, "' OR 1=1")) {
        resp->status_code = 403;
        response_append_body(resp, "{\"error\": \"SQL injection detected and blocked.\",\"details\":\"");
        sqli_detect_result_t r;
        sqli_detect(req->body, &r);
        char buf[256];
        snprintf(buf, sizeof(buf), "%s", sqli_type_name(r.type));
        response_append_body(resp, buf);
        response_append_body(resp, "\"}");
        resp->content_type[0] = '\0';
        strcpy(resp->content_type, "application/json");
        return;
    }
    response_append_body(resp, "{\"status\": \"ok\", \"message\": \"Login endpoint ready\"}");
    resp->content_type[0] = '\0';
    strcpy(resp->content_type, "application/json");
}

static void handle_route(server_state_t* ss, const http_request_t* req,
                          http_response_t* resp) {
    if (strcmp(req->url, "/") == 0 || strncmp(req->url, "/index", 6) == 0) {
        handle_security_scan(ss, req, resp);
    } else if (strncmp(req->url, "/api/login", 10) == 0) {
        handle_login(ss, req, resp);
    } else if (strncmp(req->url, "/security-report", 16) == 0) {
        handle_security_scan(ss, req, resp);
    } else {
        resp->status_code = 404;
        response_append_body(resp, "{\"error\": \"Not found\"}");
        resp->content_type[0] = '\0';
        strcpy(resp->content_type, "application/json");
    }
}

static void print_banner(void) {
    printf("\n");
    printf("  ╔══════════════════════════════════════════════╗\n");
    printf("  ║   mini-web-security Demo Server              ║\n");
    printf("  ║   Web Application Security Testing Engine    ║\n");
    printf("  ╚══════════════════════════════════════════════╝\n\n");
}

static void print_usage(void) {
    printf("Usage: demo_server [options]\n");
    printf("Options:\n");
    printf("  --port PORT        Listen port (default: 8080, simulated)\n");
    printf("  --interface IFACE  Bind interface (default: localhost)\n");
    printf("  --help             Show this help\n\n");
    printf("This is a simulated server that demonstrates HTTP request\n");
    printf("analysis and security scanning. Pipe HTTP requests via stdin.\n\n");
    printf("Example:\n");
    printf("  echo \"GET /security-report?q=test HTTP/1.1\\r\\nHost:localhost\\r\\n\\r\\n\" | demo_server\n\n");
}

static void process_simulated_requests(void) {
    server_state_t ss;
    memset(&ss, 0, sizeof(ss));
    csrf_token_generate(&ss.csrf_token);
    ratelimit_init(&ss.rate_limit, 100, 60, 300);
    owasp_report_init(&ss.owasp_report);
    csp_init(&ss.csp, false);
    csp_add_directive(&ss.csp, CSP_SRC_DEFAULT, "'self'");
    csp_add_directive(&ss.csp, CSP_SRC_SCRIPT, "'self' 'nonce-rand'");
    csp_add_directive(&ss.csp, CSP_SRC_FRAME_ANCESTORS, "'none'");

    const char* sample_requests[] = {
        "GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
        "GET /api/login HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\r\n"
            "{\"username\":\"admin\",\"password\":\"' OR 1=1--\"}",
        "GET /security-report?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1\r\n"
            "Host: localhost\r\n\r\n",
        "GET /../../../etc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\n",
        "GET /security-report?user=admin%27%20OR%201=1-- HTTP/1.1\r\n"
            "Host: localhost\r\n\r\n",
        "GET /api/login HTTP/1.1\r\nHost: localhost\r\n\r\n"
            "{\"username\":\"test\",\"password\":\"correct-horse-battery-staple\"}",
        NULL
    };
    int req_num = 0;
    for (int i = 0; sample_requests[i]; i++) {
        req_num++;
        printf("────────────── Request #%d ──────────────\n", req_num);
        http_request_t req;
        http_response_t resp;
        response_init(&resp);
        parse_request(sample_requests[i], &req);
        printf(">>> %s %s\n", req.method, req.url);
        csp_generate_header(&ss.csp, resp.headers[resp.header_count++], 1024);
        response_add_header(&resp, "X-Frame-Options: DENY");
        response_add_header(&resp, "X-Content-Type-Options: nosniff");
        response_add_header(&resp, "X-XSS-Protection: 1; mode=block");
        handle_route(&ss, &req, &resp);
        print_response(&resp);
        printf("\n");
        ss.request_count = req_num;
    }
    printf("══════════════════════════════════════════\n");
    printf("  Summary: %d requests processed\n", req_num);
    printf("  Rate limit status: %d remaining\n", ratelimit_remaining(&ss.rate_limit));
    printf("══════════════════════════════════════════\n");
}

int main(int argc, char* argv[]) {
    srand((unsigned)time(NULL));
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage();
            return 0;
        }
    }
    print_banner();
    printf("Processing simulated HTTP requests...\n\n");
    process_simulated_requests();
    return 0;
}
