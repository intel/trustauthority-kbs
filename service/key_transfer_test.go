/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package service

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	jwtlib "github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	itaConnector "github.com/intel/trustauthority-client/go-connector"
	"github.com/onsi/gomega"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/mock"
	"intel/kbs/v1/model"
	"testing"
)

var (
	publicKey    = "AQABAEWpyf19e2eARCPq/l07CvkPGIoJK+48tDtv5sB5WswB2OY63qSxb+DxOrZ/b54BNF6xeS/+s7W81z+5RKQwmewIageZZByWHp0xs6eOnhoGMpdDEHFhIfp9an5e4wP8tnoaYyzeD66J5Wgd3gX+sBv6GL1BBRq4M1bNVslXcz4w3s4xWWO2CLfgSpI1jAToEhxLxta+e5Istn4v2hXsuEmkeSL5NHrcfy7AmPhFISUoyyJZ9121jEkW/yl/oGbJegfeWwD316Af69gawFCO29xjupnfQa7XCR+YrB2XTIqDqHAbo1fQabrdG3HlyIivyayFYz6moztv0VMnoAfUFzZ70ZvcefcI2HACo2qIJmathyoisuwH3aZ0Ojcg53rSBsTK9QN4jzyYkIg0Dl0prjzrIIyTxerDf+/R/YDTNy9KC6OCluZe0xLmYwFfOcPMr6taWVEPDM7K8Rmub5Hw02mCPXNhNjOTrPxM5wqrLbX5xJ5fJs33wlv5e+XVi2agjQ=="
	nonce        = &itaConnector.VerifierNonce{}
	sgxToken     = "eyJhbGciOiJQUzM4NCIsImprdSI6Imh0dHBzOi8vYW1iZXItcG9jLXVzZXIxLnByb2plY3QtYW1iZXItc21hcy5jb20vY2VydHMiLCJraWQiOiJkN2VjN2RlZjY3NzVhMjdiZTRkNGUzODY1NGZhMWNlOGM1ZTI5MjI2YzgzZTIwNTQwMGU0NDExNzI4YjA2YTQ2ZDY5MDU5ZWU2NGM5NmY0MjE0NTU2YWNmYmQzYjcwNDYiLCJ0eXAiOiJKV1QifQ.eyJzZ3hfbXJlbmNsYXZlIjoiODNmNGU4MTk4NjFhZGVmNmZmYjJhNDg2NWVmZWE5MzM3YjkxZWQzMGZhMzM0OTFiMTdmMGQ1ZDllODIwNDQxMCIsInNneF9tcnNpZ25lciI6IjgzZDcxOWU3N2RlYWNhMTQ3MGY2YmFmNjJhNGQ3NzQzMDNjODk5ZGI2OTAyMGY5YzcwZWUxZGZjMDhjN2NlOWUiLCJzZ3hfaXN2cHJvZGlkIjowLCJzZ3hfaXN2c3ZuIjowLCJzZ3hfcmVwb3J0X2RhdGEiOiIwZTM2MjVlYTk4MGI4NGJmNzkyYTE0YWJlYzhhMDVjYjI4ZDJhMTQ4MjhkMDEyNzI3MDZlN2M1OTQwZjBmYTZiMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsInNneF9pc19kZWJ1Z2dhYmxlIjpmYWxzZSwic2d4X2NvbGxhdGVyYWwiOnsicWVpZGNlcnRoYXNoIjoiYjJjYTcxYjhlODQ5ZDVlNzk5NDUxYjRiZmU0MzE1OWEwZWU1NDgwMzJjZWNiMmMwZTQ3OWJmNmVlM2YzOWZkMSIsInFlaWRjcmxoYXNoIjoiZjQ1NGRjMWI5YmQ0Y2UzNmMwNDI0MWUyYzhjMzdhMmFlMjZiMDc3ZjJjNjZiOTE5ODQzMzY1MzE4YTU5MzMyYyIsInFlaWRoYXNoIjoiNGRjZDUwMWVjZTdhNzY3NWJmMDFjZDEyM2RmYmZiZDEwYzEyOTk4ZWRkNGYyMDE5ZjMxNGUxZTM1OTE4NmI5ZSIsInF1b3RlaGFzaCI6ImU0OTVjMDZjYWFmMDRkMzc4ZmQ4MDFlMWRjMDg0ZjczZDRkZDkyYjExMmVjZmZkMWU4ZTM4ODk0MWY0YzUxMDQiLCJ0Y2JpbmZvY2VydGhhc2giOiJiMmNhNzFiOGU4NDlkNWU3OTk0NTFiNGJmZTQzMTU5YTBlZTU0ODAzMmNlY2IyYzBlNDc5YmY2ZWUzZjM5ZmQxIiwidGNiaW5mb2NybGhhc2giOiJmNDU0ZGMxYjliZDRjZTM2YzA0MjQxZTJjOGMzN2EyYWUyNmIwNzdmMmM2NmI5MTk4NDMzNjUzMThhNTkzMzJjIiwidGNiaW5mb2hhc2giOiJlYzFjZWYzNzNiNWIyOThkN2JkZTM4NTI5NTE0NWQ5MmU0ZGU0MTZkMGQ1OTRlYzQ1NWVmNGU3YTMyMzUwMGY0In0sImF0dGVzdGVyX2hlbGRfZGF0YSI6IkFRQUJBRVdweWYxOWUyZUFSQ1BxL2wwN0N2a1BHSW9KSys0OHREdHY1c0I1V3N3QjJPWTYzcVN4YitEeE9yWi9iNTRCTkY2eGVTLytzN1c4MXorNVJLUXdtZXdJYWdlWlpCeVdIcDB4czZlT25ob0dNcGRERUhGaElmcDlhbjVlNHdQOHRub2FZeXplRDY2SjVXZ2QzZ1grc0J2NkdMMUJCUnE0TTFiTlZzbFhjejR3M3M0eFdXTzJDTGZnU3BJMWpBVG9FaHhMeHRhK2U1SXN0bjR2MmhYc3VFbWtlU0w1TkhyY2Z5N0FtUGhGSVNVb3l5Slo5MTIxakVrVy95bC9vR2JKZWdmZVd3RDMxNkFmNjlnYXdGQ08yOXhqdXBuZlFhN1hDUitZckIyWFRJcURxSEFibzFmUWFicmRHM0hseUlpdnlheUZZejZtb3p0djBWTW5vQWZVRnpaNzBadmNlZmNJMkhBQ28ycUlKbWF0aHlvaXN1d0gzYVowT2pjZzUzclNCc1RLOVFONGp6eVlrSWcwRGwwcHJqenJJSXlUeGVyRGYrL1IvWURUTnk5S0M2T0NsdVplMHhMbVl3RmZPY1BNcjZ0YVdWRVBETTdLOFJtdWI1SHcwMm1DUFhOaE5qT1RyUHhNNXdxckxiWDV4SjVmSnMzM3dsdjVlK1hWaTJhZ2pRPT0iLCJ2ZXJpZmllcl9ub25jZSI6eyJ2YWwiOiJUV3BhWW5KdlNWbHBlakJNY1ZKdFVIUlBPVzV5TjI5RVMyNUJRVGxwY210S05DOVVRa3A1TDJKMFVHWkJjMWRsY1hZMGEyWmFiMlZzUTBvcmNYZ3JNa3BYVVU4NFFqTkJhV2xMTkhsR1FXRnBSemhCWVdjOVBRPT0iLCJpYXQiOiJNakF5TXkweE1pMHhOaUF4T0RveE56bzFPU0FyTURBd01DQlZWRU09Iiwic2lnbmF0dXJlIjoiTEFTRVg3TDFKY3FNeEUxVDBzaDVDdTk5aGVqaHhDWmV0QVpXanNhMUdhSTBPeTh6ZnMzWW1DbVVoOExOZEJuMWhlcjc1L3VPREQ3bWFFV2R4NHNaTkhteXhLdUtwaWNabXMvbTMySTJlU0dzLyt0SCtVWlEzLytMajJMNjdlOUVMNVo4NWNLUGFKU1cyRmZQQWkrbXk2SGtGY0ZweE01Mzd6eEgvcWhKeDJVdjlXQ1NxdmRJeDlPaVRMdlQyc3ZGdzY3cXBVNFhQeGVsM1llZU85VTk0aWExNGUrVkp4WlJxUTVEbE1vOWwxZDBIZjhRK3YrY0w0Wmd6TEp1SHIzQXpQZ0JJY3VPYmN0eTlMd2JVQmRCcWRKNWZaWTBGcW1JSnJoMXZFUmlCYmV6bklJV2ZJbnczWVoyNS9wV0FCOVJXdHYrZENlSjZBcUlkQ2VCM2pGLzBGbG9DTUlDaGl5WkgwM1RTRXlpTnRlWElCR0dDUytmYkZqREZ3SHR4ZGQxVUYzcXpBcjVRSmtlUWE1elgxdjh1bUFLSXN0TWIwNzR2QXVqZzF4U3hxZTk5TUJaeWc5QVdiNy93a0JoZWJybE5oOUdlMWhlSzE2WG5RSGdqVW82MXVNOUxjTmIvcm5TSS9hWmtQMEdBTFZENHY1WCt3bmcyYngrNDI5QTNMc0YifSwiYXR0ZXN0ZXJfdGNiX3N0YXR1cyI6Ik9VVF9PRl9EQVRFIiwiYXR0ZXN0ZXJfYWR2aXNvcnlfaWRzIjpbIklOVEVMLVNBLTAwNTg2IiwiSU5URUwtU0EtMDA2MTQiLCJJTlRFTC1TQS0wMDYxNSIsIklOVEVMLVNBLTAwNjU3IiwiSU5URUwtU0EtMDA3MzAiLCJJTlRFTC1TQS0wMDczOCIsIklOVEVMLVNBLTAwNzY3IiwiSU5URUwtU0EtMDA4MjgiLCJJTlRFTC1TQS0wMDgzNyJdLCJhdHRlc3Rlcl90eXBlIjoiU0dYIiwidmVyaWZpZXJfaW5zdGFuY2VfaWRzIjpbIjkwYzYyMjY0LWU4NTQtNGZjNi05YzlkLWM3NWM4NWRhYjM1MSIsIjMwY2JmNDZkLTU5YjAtNGQ5Ni1hOTY4LWQzZDU0YzE2ZTAzNSIsIjgxZTVjYjFlLWRiYmItNDZlMi1iNmM2LTU4MjdmNzkzYjNlZiJdLCJkYmdzdGF0IjoiZGlzYWJsZWQiLCJlYXRfcHJvZmlsZSI6Imh0dHBzOi8vYW1iZXItcG9jLXVzZXIxLnByb2plY3QtYW1iZXItc21hcy5jb20vZWF0X3Byb2ZpbGUiLCJpbnR1c2UiOiJnZW5lcmljIiwidmVyIjoiMS4wLjAiLCJleHAiOjE3MDI3NTA5NzksImp0aSI6ImNjYWZlMWRmLTkyOWUtNDU5Ni1hZDE2LWQwMzk5ODYyMWIxNCIsImlhdCI6MTcwMjc1MDY3OSwiaXNzIjoiSW50ZWwgVHJ1c3QgQXV0aG9yaXR5IiwibmJmIjoxNzAyNzUwNjc5fQ.OYgfNXW3UP7y9r27mIJUsPz_Tj8_akBWQiDoXZcfFRbQKxySIX8VWz0cCDpG_838yDU2zrbqigbf9ux73syWINCZhceBNsxcU7gUGkEoAluv3grsBl_x39USGXCj9GnnuzqdNznjIIjjEO3PmMwkxeCQ_PNwNzkf611aETQnm-a1Xd34Iv9YwERpRYIrknlk2MTKLDn9QWi_lcq95YZYHuKnD8Hp9dnBwTElr5Qj5PPPIe48UVfwYJlFIqAG0fRTnRGHQtCDvOAFbPsgLleNSzbvu2Ja03A7PP08_73KiYj5sb0iqrW7hiUwEQmwz-mCQ8ppJqFgSKF4AqlxJJKb0PIDtQ8gEFlxwz6Jcw6qISnpGuflb41NSshIn7bNHEH8vRPsigHHiqgM9koMxzMcwJ7NCcq76HPaBGNWuu5Ho0tYfebWYyJ2YH2PJ0TAVgfXE5ZcqjVdtE_pqmnLNOOyGYVk_oUqERNcdWCTwzAlbqPr5ijRRI5YUwLKrHuV7_hG"
	tdxToken     = "eyJhbGciOiJQUzM4NCIsImprdSI6Imh0dHBzOi8vcG9ydGFsLnRydXN0YXV0aG9yaXR5LmludGVsLmNvbS9jZXJ0cyIsImtpZCI6Ijc5ZDgwNzExYjc1NGNjZWIzMDdkNDI3OGRjNTk5NTdmMjdlYjU1YThlMzNkM2I4MjQ5Njc5NzU4NDNkY2JmMjFkZjkyNGVlYmFmOTNmY2UxODZmZDI5MWQzNjgxNzc4NSIsInR5cCI6IkpXVCJ9.eyJ0ZHhfdGVlX3RjYl9zdm4iOiIwMzAwMDUwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsInRkeF9tcnNlYW0iOiIyZmQyNzljMTYxNjRhOTNkZDViZjM3M2Q4MzQzMjhkNDYwMDhjMmI2OTNhZjllYmI4NjViMDhiMmNlZDMyMGM5YTg5YjQ4NjlhOWZhYjYwZmJlOWQwYzVhNTM2M2M2NTYiLCJ0ZHhfbXJzaWduZXJzZWFtIjoiMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwidGR4X3NlYW1fYXR0cmlidXRlcyI6IjAwMDAwMDAwMDAwMDAwMDAiLCJ0ZHhfdGRfYXR0cmlidXRlcyI6IjAwMDAwMDEwMDAwMDAwMDAiLCJ0ZHhfeGZhbSI6ImU3MDAwMDAwMDAwMDAwMDAiLCJ0ZHhfbXJ0ZCI6IjVmNTNjMzg4MTI0MmE1YjQxODg1NDkyM2JiNGFkZWMzNGM3MmFhNGI1NzBkNTI2MTc5ZDYzZjllZTZlNGNlZmI2YWJkNGYwZjM1ZTVlNmUyOTY1NWE2MGQ5MGJjZjI3ZiIsInRkeF9tcmNvbmZpZ2lkIjoiMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwidGR4X21yb3duZXIiOiIwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAiLCJ0ZHhfbXJvd25lcmNvbmZpZyI6IjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsInRkeF9ydG1yMCI6IjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsInRkeF9ydG1yMSI6IjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsInRkeF9ydG1yMiI6IjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsInRkeF9ydG1yMyI6IjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsInRkeF9yZXBvcnRfZGF0YSI6IjRkMjk3YWFiMTBhMWI0MTQ2YWUxYzRkYWI1OGJmNjlkZGVjNzZhN2UxN2JmNGIxMDhkNmU3ZTFjNzg5YzY0MzU0N2M2YmRjZWMyMGYyZjdlNGMwY2RhZDJjYWM1ZDZhZmRkYmIzNDFjZDdjNTA3NDk0YjQwOTU0MWYyYzlmZGNhIiwidGR4X3NlYW1zdm4iOjMsInRkeF90ZF9hdHRyaWJ1dGVzX2RlYnVnIjpmYWxzZSwidGR4X3RkX2F0dHJpYnV0ZXNfc2VwdHZlX2Rpc2FibGUiOnRydWUsInRkeF90ZF9hdHRyaWJ1dGVzX3Byb3RlY3Rpb25fa2V5cyI6ZmFsc2UsInRkeF90ZF9hdHRyaWJ1dGVzX2tleV9sb2NrZXIiOmZhbHNlLCJ0ZHhfdGRfYXR0cmlidXRlc19wZXJmbW9uIjpmYWxzZSwidGR4X2lzX2RlYnVnZ2FibGUiOmZhbHNlLCJ0ZHhfY29sbGF0ZXJhbCI6eyJxZWlkY2VydGhhc2giOiJiMmNhNzFiOGU4NDlkNWU3OTk0NTFiNGJmZTQzMTU5YTBlZTU0ODAzMmNlY2IyYzBlNDc5YmY2ZWUzZjM5ZmQxIiwicWVpZGNybGhhc2giOiJmNDU0ZGMxYjliZDRjZTM2YzA0MjQxZTJjOGMzN2EyYWUyNmIwNzdmMmM2NmI5MTk4NDMzNjUzMThhNTkzMzJjIiwicWVpZGhhc2giOiJiMTIzMjFhNGRlNzY4MDA1Yzg2OTczNGFiYTNiZWEyY2VmNWE1YWFhMDYxMTVhZmE4NWZmYzcwOWJjZWZmMGZjIiwicXVvdGVoYXNoIjoiZjE2YWE3NmRjNmQ1Y2U4ZmQwNDg0NDI3ZmVmODgyMjBkYzkzMDY2YjI3OTFjYmJkNDkzY2M2MmI5NGM3OWNiMSIsInRjYmluZm9jZXJ0aGFzaCI6ImIyY2E3MWI4ZTg0OWQ1ZTc5OTQ1MWI0YmZlNDMxNTlhMGVlNTQ4MDMyY2VjYjJjMGU0NzliZjZlZTNmMzlmZDEiLCJ0Y2JpbmZvY3JsaGFzaCI6ImY0NTRkYzFiOWJkNGNlMzZjMDQyNDFlMmM4YzM3YTJhZTI2YjA3N2YyYzY2YjkxOTg0MzM2NTMxOGE1OTMzMmMiLCJ0Y2JpbmZvaGFzaCI6IjE1ODYxZTE5YTU5NDBhZGVmYzhjMWM4YTYwNzFmODNiYTY5N2RmMTFhMjQ5NDFkN2ZkM2Y1YzlmNzRiYTg2M2UifSwiYXR0ZXN0ZXJfaGVsZF9kYXRhIjoiTUlJQm9qQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FZOEFNSUlCaWdLQ0FZRUFwS29ESVU5Ry9IUGZsUkZ3K0hQN1J5N2dxK3dSK2twRjNnaGdRb3o2V1BpN005L08rM0psSFpYcFZWSEZ6MDdKZGRhOXhvTXN2S0QzTGdhYkowbkN1UTlzakUrWTZ4aVc2bmNBRHVLS3lCWTVRdFB1eHZLNkxmMnNhQ0RsZ00zcVVaL3lnZEU4T0pEK1FYTTBtWUtKTVVnYmN5MlA2dUZ4NUQ1MXNGTFF2VG9WOHc3UVMwN0Foc1hjaTI0dkw2aVVIMzB3MWhWUmkwWUErSDc0V3hIYzVTOUpabGdoTjhuVXFoVGorbTdNSitEckxMY3hCbWtpUmVZd2JzNFV6S3YvWEQ2MDR4LzkrVStDZk51UldJL3h1KzArRW4ydUw0ZU1xaXlsakNSSjRqbWdMNDV0QkhtUUMrTlQ1UnI5ZzVjOExQNkVGcDRaVTRxVlBCQ3E0Nk43Rk1UbERWN01hSy9Nb1F3U1pZVVlUWXFFdVlaSGp5ckwrcVVFdmsrWkFMRXBhOGg1MFJuaXBHUk1aK0tlSytmcVRxNDZzdGlUbWx5SWkrM1U3TmJ1LzZYZXRhVVp6SkhWOThjM1VVa0Zlb0RxSmZlMmFUTHhXcGV1amJqRENnZzRPMjU1KzN1aUhvSlg5SXZnNHc5NW51ZmkxRDUvNThYYUNOdTYveXdpZXRKL0FnTUJBQUU9IiwidmVyaWZpZXJfbm9uY2UiOnsidmFsIjoiWlVWemFqQjRWV1pqYUZFNFNteEtObGxhTDNwamRuRkljbEpGZEVGWmVXcDVSbTlIVEV0SE1FdHdOMjl1ZDFWUVpGRlRTWGQ2UnpCVlN6QXdlbE14YkZNMWVrdEhZekJTVFRkVmNEQm9kelF4Vm14WWVtYzlQUT09IiwiaWF0IjoiTWpBeU15MHhNaTB3TlNBd01Eb3dPVG94TUNBck1EQXdNQ0JWVkVNPSIsInNpZ25hdHVyZSI6Ik1RV1lsdnBvTHRXc3VWMyt0OVFQTHk1VXByLzVtKzZHUitMOXUvUHV5M01wM0k4SjBUcmh0dVhIVlJGc2tWZUNDTnlETlVoK2pGaEx3a1k0VzM2TXgzNk01ejFaYzRWd0Y2Rm9LeWQ4eWpCMzlmV3V5RHBna3hiYUdxVkNTU080YVJzK0ozd2JaRWc4OFhUZGhxS0NkV3ZFUHA1NitUaEVrSVgxQVRERVZTMDJHK3kwUWlSNVdZNGtqaXQ1bFRsZUVNbk5rU2JNT25yZlhlR1NDRXR2eWUyUTNJQUR1aldWWmFlZVdTSEtjVkdiSG1OOVI2dzB5cUduTVlBUmVxaHRHSDltL0pWZHVJOThZMVpWR0ZHb0NzUGw0dnM4UU9obDJ0QVk2VW43bE1KYXVYVDNSbTlYRC9iejVJZTVKWktLMFdmSk1JVzlWclc5bjlTQmpEbFZmT25jbHdTNURkMTZjUTBIbml1ZWpLZ1RsNVBibEUvWlJOSXg3OEt3Y1EySmRYRkloWi9YSTY0VHVNUkplU1BacURVcVJHTlVFTVpGb21YSTJIZ2s3WkNaWXZyUlV6VXJhWFdyZ3A3OWowRXVpdHQ4dnk4WjErQXdaaHd6THlVOEdWazlKYm1DWVd5TWJUVVc4TU5SODVENjZIcE83SER0NVlMQTg2Z3d6Wk5LIn0sImF0dGVzdGVyX3RjYl9zdGF0dXMiOiJPdXRPZkRhdGUiLCJhdHRlc3Rlcl90Y2JfZGF0ZSI6IjIwMjMtMDItMTVUMDA6MDA6MDBaIiwiYXR0ZXN0ZXJfYWR2aXNvcnlfaWRzIjpbIklOVEVMLVNBLTAwODM3Il0sImF0dGVzdGVyX3R5cGUiOiJURFgiLCJ2ZXJpZmllcl9pbnN0YW5jZV9pZHMiOlsiNmY1NmY4Y2EtZTU0Ni00YmJkLWEwMjAtZTZhYjJiM2QyNjQ2IiwiMGI1NzMyYTMtZmZjOC00NjRiLTgyZTEtNWY2ZjRjNjcxMjkyIiwiM2FhOGZlYWItOGU0ZC00ZWIxLTliYzMtZmQ1NTIwMmY1ZTI2Il0sImRiZ3N0YXQiOiJkaXNhYmxlZCIsImVhdF9wcm9maWxlIjoiaHR0cHM6Ly9wb3J0YWwudHJ1c3RhdXRob3JpdHkuaW50ZWwuY29tL2VhdF9wcm9maWxlIiwiaW50dXNlIjoiZ2VuZXJpYyIsInZlciI6IjEuMC4wIiwiZXhwIjoxNzAxNzM1MjUwLCJqdGkiOiJmZjMxZDcxYS0xOTdkLTRhNmQtODRkNi05MjBiMzkwODFhMDMiLCJpYXQiOjE3MDE3MzQ5NTAsImlzcyI6IkludGVsIFRydXN0IEF1dGhvcml0eSIsIm5iZiI6MTcwMTczNDk1MH0.nLybA1DYcA5VUVKGM4lao-KkTY3B7Eb4yw7tu0mj52iTbZHCbbb1GssiYJGn6brL5vdgmsoCa_n3cQgqRW3VHGbifKAbdm6uoA3sCcCskRjrhE53g3mP43DF_9Zt7u2KTI0wTqJWbb7RJbcNH7MowEwhyjtrnDJ8nYI8brx-kFDt5uEb_f-rZU_yXCa8KW68koTmBRqBF36UdRmuzN3IfsuyhcR23li90RufX8pcqhUGTfhgdcEG-hwomDY7OwGMRfL7t0-6_u5glQuPyfBU6aWgCrf2eToM0_skrIv9wP4DFD7sBYL6B2929bCdnOVwFlXukwlMXDYhzXwjz3Hs6de6gru2R869JGf5-GlEkJpjS4W7pVD2D1Df_w5Do2Ln_1L98qW8B4EpAbtopq2U8lEBce_uyxBDbb18WM0bQ8zkNKjLx7Y9jwU2hEAydxmorBmFKbu9eNKbyjaF3zWpIa9QeLi5tVV7tZHjuUbPrRIBw3BWtj_0rDO1dfVZYtXm"
	sgxTokenResp = itaConnector.GetTokenResponse{
		Token:   sgxToken,
		Headers: nil,
	}
	tdxTokenResp = itaConnector.GetTokenResponse{
		Token:   tdxToken,
		Headers: nil,
	}
)

func TestKeyTransferRSA(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	itaClientConnector.On("GetToken", mock.Anything).Return(sgxTokenResp, nil).Once()
	jwtToken := parseJWTToken(sgxToken, []byte(""))
	itaClientConnector.On("VerifyToken", mock.Anything).Return(jwtToken, nil).Once()

	kmipClient.On("GetKey", mock.Anything, mock.Anything).Return(key, nil)
	kmipKeyManager.On("TransferKey", mock.AnythingOfType("*model.KeyAttributes")).Return([]uint8(key), nil)

	svc := LoggingMiddleware()(svcInstance)
	g.Expect(svc).NotTo(gomega.BeNil())
	nonce := &itaConnector.VerifierNonce{}

	transReq := &model.KeyTransferRequest{
		Quote:         []byte(""),
		VerifierNonce: nonce,
		RuntimeData:   []byte(""),
		EventLog:      []byte(""),
	}

	request := TransferKeyRequest{
		KeyId:              rsaKeyId,
		AttestationType:    "SGX",
		KeyTransferRequest: transReq,
	}

	_, err := svc.TransferKeyWithEvidence(context.Background(), request)
	g.Expect(err).NotTo(gomega.HaveOccurred())
}
func TestSGXKeyTransfer(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	itaClientConnector.On("GetToken", mock.Anything).Return(sgxTokenResp, nil).Once()
	jwtToken := parseJWTToken(sgxToken, []byte(""))
	itaClientConnector.On("VerifyToken", mock.Anything).Return(jwtToken, nil).Once()

	kmipClient.On("GetKey", mock.Anything, mock.Anything).Return(key, nil)
	kmipKeyManager.On("TransferKey", mock.AnythingOfType("*model.KeyAttributes")).Return([]uint8(key), nil)

	svc := LoggingMiddleware()(svcInstance)
	g.Expect(svc).NotTo(gomega.BeNil())
	nonce := &itaConnector.VerifierNonce{}

	transReq := &model.KeyTransferRequest{
		Quote:         []byte(""),
		VerifierNonce: nonce,
		RuntimeData:   []byte(""),
		EventLog:      []byte(""),
	}

	request := TransferKeyRequest{
		KeyId:              rsaKeyId,
		AttestationType:    "SGX",
		KeyTransferRequest: transReq,
	}

	_, err := svc.TransferKeyWithEvidence(context.Background(), request)
	g.Expect(err).NotTo(gomega.HaveOccurred())
}

func TestTDXKeyTransfer(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	itaClientConnector.On("GetToken", mock.Anything).Return(tdxTokenResp, nil).Once()
	jwtToken := parseJWTToken(tdxToken, []byte(""))
	itaClientConnector.On("VerifyToken", mock.Anything).Return(jwtToken, nil).Once()

	kmipClient.On("GetKey", mock.Anything, mock.Anything).Return(key, nil)
	kmipKeyManager.On("TransferKey", mock.AnythingOfType("*model.KeyAttributes")).Return([]uint8(key), nil)

	svc := LoggingMiddleware()(svcInstance)
	g.Expect(svc).NotTo(gomega.BeNil())
	nonce := &itaConnector.VerifierNonce{}

	transReq := &model.KeyTransferRequest{
		Quote:         []byte(""),
		VerifierNonce: nonce,
		RuntimeData:   []byte(""),
		EventLog:      []byte(""),
	}

	request := TransferKeyRequest{
		KeyId:              uuid.MustParse("ed37c360-7eae-4250-a677-6ee12adce8e3"),
		AttestationType:    "TDX",
		KeyTransferRequest: transReq,
	}

	_, err := svc.TransferKeyWithEvidence(context.Background(), request)
	g.Expect(err).NotTo(gomega.HaveOccurred())
}

func TestKeyTransferInvalidAttestationType(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	itaClientConnector.On("GetToken", mock.Anything).Return(sgxTokenResp, nil).Once()
	jwtToken := parseJWTToken(sgxToken, []byte(""))
	itaClientConnector.On("VerifyToken", mock.Anything).Return(jwtToken, nil).Once()

	kmipClient.On("GetKey", mock.Anything, mock.Anything).Return(key, nil)
	kmipKeyManager.On("TransferKey", mock.AnythingOfType("*model.KeyAttributes")).Return([]uint8(key), nil)

	svc := LoggingMiddleware()(svcInstance)
	g.Expect(svc).NotTo(gomega.BeNil())

	transReq := &model.KeyTransferRequest{
		Quote:         []byte(""),
		VerifierNonce: nonce,
		RuntimeData:   []byte(""),
		EventLog:      []byte(""),
	}

	request := TransferKeyRequest{
		KeyId:              rsaKeyId,
		AttestationType:    "Invalid",
		KeyTransferRequest: transReq,
	}

	_, err := svc.TransferKeyWithEvidence(context.Background(), request)
	g.Expect(err).To(gomega.HaveOccurred())
}

func TestKeyTransferInvalidKeyId(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	itaClientConnector.On("GetToken", mock.Anything).Return(sgxTokenResp, nil).Once()
	jwtToken := parseJWTToken(sgxToken, []byte(""))
	itaClientConnector.On("VerifyToken", mock.Anything).Return(jwtToken, nil).Once()

	kmipClient.On("GetKey", mock.Anything, mock.Anything).Return(key, nil)
	kmipKeyManager.On("TransferKey", mock.AnythingOfType("*model.KeyAttributes")).Return([]uint8(key), nil)

	svc := LoggingMiddleware()(svcInstance)
	g.Expect(svc).NotTo(gomega.BeNil())

	transReq := &model.KeyTransferRequest{
		Quote:         []byte(""),
		VerifierNonce: nonce,
		RuntimeData:   []byte(""),
		EventLog:      []byte(""),
	}

	request := TransferKeyRequest{
		KeyId:              uuid.New(),
		AttestationType:    "SGX",
		KeyTransferRequest: transReq,
	}

	_, err := svc.TransferKeyWithEvidence(context.Background(), request)
	g.Expect(err).To(gomega.HaveOccurred())
}

func TestKeyTransferInvalidSecretKey(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	itaClientConnector.On("GetToken", mock.Anything).Return(sgxTokenResp, nil).Once()
	jwtToken := parseJWTToken(sgxToken, []byte(""))
	itaClientConnector.On("VerifyToken", mock.Anything).Return(jwtToken, nil).Once()

	kmipKeyManager.On("TransferKey", mock.AnythingOfType("*model.KeyAttributes")).Return(nil, errors.Errorf("Invalid Key"))

	svc := LoggingMiddleware()(svcInstance)
	g.Expect(svc).NotTo(gomega.BeNil())

	transReq := &model.KeyTransferRequest{
		Quote:         []byte(""),
		VerifierNonce: nonce,
		RuntimeData:   []byte(""),
		EventLog:      []byte(""),
	}

	request := TransferKeyRequest{
		KeyId:              uuid.MustParse("ed37c360-7eae-4250-a677-6ee12adce8e3"),
		AttestationType:    "TDX",
		KeyTransferRequest: transReq,
	}

	_, err := svc.TransferKeyWithEvidence(context.Background(), request)
	g.Expect(err).To(gomega.HaveOccurred())
}

func TestGetSecretKey(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	tmpId := uuid.New()
	_, _, err := getSecretKey(kRemoteManager, tmpId)

	g.Expect(err).To(gomega.HaveOccurred())
}

// ParseJWTToken parses a JWT token string and returns a jwt.Token object.
func parseJWTToken(tokenString string, secretKey []byte) *jwtlib.Token {
	token, _ := jwtlib.Parse(tokenString, func(token *jwtlib.Token) (interface{}, error) {
		return secretKey, nil
	})

	return token
}

func loadPublicKey(userData []byte) ([]byte, error) {
	pubKeyBlock, _ := pem.Decode(userData)
	pubKeyBytes, err := x509.ParsePKIXPublicKey(pubKeyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	// Public key format : <exponent:E_SIZE_IN_BYTES><modulus:N_SIZE_IN_BYTES>
	pub := pubKeyBytes.(*rsa.PublicKey)
	pubBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(pubBytes, uint32(pub.E))
	pubBytes = append(pubBytes, pub.N.Bytes()...)
	return pubBytes, nil
}
