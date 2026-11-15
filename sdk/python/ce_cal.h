/* CAL (cell auth language) C ABI. Both arguments are NUL-terminated UTF-8; the result is JSON
 * ({"ok": true, ...} or {"ok": false, "error": {...}}) and must be freed with ce_cal_free.
 * Ops: parse, compile, sign, explain, decompile, verify (docs/CAL.md section 8). */
#ifndef CE_CAL_H
#define CE_CAL_H
char *ce_cal_call(const char *op, const char *request_json);
void ce_cal_free(char *response);
#endif
