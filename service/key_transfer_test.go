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
	tdxToken     = "eyJhbGciOiJQUzM4NCIsImprdSI6Imh0dHBzOi8vcG9ydGFsLnBpbG90LnRydXN0YXV0aG9yaXR5LmludGVsLmNvbS9jZXJ0cyIsImtpZCI6ImZlMmNjZTI0NGU2ODc3YzhhZDg0YjFmM2JjY2JhMWViZDJkMTJlYmMzNGQ4NzNkYzVlYTcxYjBiNWQxMmE3OWM1MzM0Mzk3YzFhMmVhZWIyNTY1NzEzM2E5ZDlmNmY2OCIsInR5cCI6IkpXVCJ9.eyJ0ZHhfdGVlX3RjYl9zdm4iOiIwNDAwMDYwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsInRkeF9tcnNlYW0iOiI0OGZhNjk5NDlkYjA4MDAyZWU4NDI1Mjg0N2Y1NzI5ODhiMWQ2ZTU2OGVjMTM1M2Y2NGNiNmMwZmQ5MDUzNzVmNjlhZDk1OWMwZWFmNzc0N2FjNzBhMzkyNzg5MzAyYTEiLCJ0ZHhfbXJzaWduZXJzZWFtIjoiMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwidGR4X3NlYW1fYXR0cmlidXRlcyI6IjAwMDAwMDAwMDAwMDAwMDAiLCJ0ZHhfdGRfYXR0cmlidXRlcyI6IjAwMDAwMDEwMDAwMDAwMDAiLCJ0ZHhfeGZhbSI6ImU3MWEwNjAwMDAwMDAwMDAiLCJ0ZHhfbXJ0ZCI6ImI3ZGU4MDE2MGU0YjVjMmE1M2ZjOWY3ZmQ3MjgzMzQ1NTU2MzQzMWEwNmFlMDIyMjIxYjRmODFjMTFlYTU1ZGQ0ZDg5N2QyYTUzM2U4NzdjNjg0NTc3YjQ4MDNkMzllYyIsInRkeF9tcmNvbmZpZ2lkIjoiMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwidGR4X21yb3duZXIiOiIwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAiLCJ0ZHhfbXJvd25lcmNvbmZpZyI6IjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsInRkeF9ydG1yMCI6IjE1YjAwZTg4YmNiNzYyZTVlY2IwNDFiZDEzMmUwZmIzMzU3MmJjODg0NjlkZjUzZjA2ZjZmYmQzNGUxMzJmMjNhMzAxMDMxY2U1MzU4Y2JiNmNjZGNhMGFhZGJhMzI4ZCIsInRkeF9ydG1yMSI6IjQ1ZDhmYzBiNjAxOGE1NjU0NzQ0MWZiODA4MWM3ZWU2ZGUwNGU2MzIyMWM3ZTJiMzdkNGQ3MWZlMzYyMzEwN2U3ZTQ5NjY3ZjJkNmIyNTk3YmM1ZjA2NjNjODRiNjQ1NyIsInRkeF9ydG1yMiI6IjIxNzRhMTc2NDVkNWY1N2UxN2RkZDI4Zjk1ZTE4YzJkNmZlNzVhMTkyNGMwMGU4NjFiNTcwZTdiZTJhZGVkNjM3NjY5ZTFiMDE4MTY2NWMzZTk3YWI0MzI1NjYwZWQ3NiIsInRkeF9ydG1yMyI6IjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsInRkeF9yZXBvcnRfZGF0YSI6IjExNjYxYWVmZTVhMTQwN2M3NDBhZTNjMTNlMzY5MzBhN2ZiNTFhYTI5YWZiNDQ0YjUyNTRiZGEwMjUyZTk2MzgyZDA3YmNkNmE0MmU3ZGI5ODFmZmY0MDU4NWJiMTI2MDU5YTA5ZGYzZGE0Y2RmYTU2YjI5YWVlYTVjOGE5OWE2IiwidGR4X3NlYW1zdm4iOjQsInRkeF90ZF9hdHRyaWJ1dGVzX2RlYnVnIjpmYWxzZSwidGR4X3RkX2F0dHJpYnV0ZXNfc2VwdHZlX2Rpc2FibGUiOnRydWUsInRkeF90ZF9hdHRyaWJ1dGVzX3Byb3RlY3Rpb25fa2V5cyI6ZmFsc2UsInRkeF90ZF9hdHRyaWJ1dGVzX2tleV9sb2NrZXIiOmZhbHNlLCJ0ZHhfdGRfYXR0cmlidXRlc19wZXJmbW9uIjpmYWxzZSwidGR4X2lzX2RlYnVnZ2FibGUiOmZhbHNlLCJ0ZHhfY29sbGF0ZXJhbCI6eyJxZWlkY2VydGhhc2giOiJiMmNhNzFiOGU4NDlkNWU3OTk0NTFiNGJmZTQzMTU5YTBlZTU0ODAzMmNlY2IyYzBlNDc5YmY2ZWUzZjM5ZmQxIiwicWVpZGNybGhhc2giOiJmNDU0ZGMxYjliZDRjZTM2YzA0MjQxZTJjOGMzN2EyYWUyNmIwNzdmMmM2NmI5MTk4NDMzNjUzMThhNTkzMzJjIiwicWVpZGhhc2giOiI3YWNhZDgzNzY5MmNjY2NlYzBiZTczNmQwY2RlNmFhYjQ2NWQ2ODU2Y2MxZmQyYzIzN2ZmMDM5MzZkNzU2NjY0IiwicXVvdGVoYXNoIjoiNTYzMzJmNDRiZjUzMzFkYTgwYzNhN2Y2NzlhMzY1NTdhNTFlOGI1Y2RkM2M1YjBhNjU1OWM3Mjk2ODE1ZGExOSIsInRjYmluZm9jZXJ0aGFzaCI6ImIyY2E3MWI4ZTg0OWQ1ZTc5OTQ1MWI0YmZlNDMxNTlhMGVlNTQ4MDMyY2VjYjJjMGU0NzliZjZlZTNmMzlmZDEiLCJ0Y2JpbmZvY3JsaGFzaCI6ImY0NTRkYzFiOWJkNGNlMzZjMDQyNDFlMmM4YzM3YTJhZTI2YjA3N2YyYzY2YjkxOTg0MzM2NTMxOGE1OTMzMmMiLCJ0Y2JpbmZvaGFzaCI6IjhiZjI2ZDVlY2MxZjU0MDQ1ODdlZmZhMzU3Yjg1NTllZGMwNjM5OTA1ZjRkNjk1N2ZmMTU3MmYzM2VhNTRlOWQifSwiYXR0ZXN0ZXJfaGVsZF9kYXRhIjoiQUFFQUFlWllwZGFjaHlTVEl3TGZ5NUtFQkNXRU5ISUN6RXBaVHRRbE9ycXVMRWJETGFGQkxDMEZoMlg2bUtkOGIyVVQ2cFgwUzBwZjVHcUFQMUMxQ1Y2OXdBdkdIQVB3RFFKY3RCQUJHV3Y0Vk1EL2EvY0d4M2NNM0FmVVFTK0Uyb0c1bHpOcHIzTTNwdTRxczFlUk9Tekx6Z2E2dkJvdC8rNXFoZk5GakkrN01RT2xidVNRTDZha2U2T3RTRnRPT3M1c3hMVjRkVlRZUTh2MkxiN3Z3aTBzeWJUM1VpZHNlNGNMa2ZtVWx1blBndGJjRWtzUi9RNnY5WHJPTWVjS0pCZjN5UTdsdHpGclhZWE1hQlZFTmdwRFA4TDNOanZNV0tPS1loNHhNdFJVeFoxQlpnSjlaZVpua0h3RHN1eXlBSkcwNi9oMUtZSVdiajBRZUlKV1ZxRzVydnpkSUxTSzVVRmEzdllvS1VWU3drMDhIWjg0Rk91K1dveDNPYjdiZUR5NnJLb3lBNWhxWjlkNlJQVkJzKzVEU0o1dUw0REJWdU94bzJQeVI0WVA5cEpFZnVjclFjaHI3d2kyeXU2WGQ0cFZadlByRTRwendzMWZCLzJOR3pqcHhuS0I1cFM3SHJjQ1BMODBSQ1VwQTZBcmJDblJBRzMzSlh6c1RINTBOSUlSeVE9PSIsInZlcmlmaWVyX25vbmNlIjp7InZhbCI6Ik9HUkZOMU5rYlRndlVIVklNMjlVU0RrMlluaHVOREZRV0ZkWWJrVjZiVnBOYTJGRFNHTllaazl5WkRaV1ZUVjJXV281Wkc1emFDdENVemczZVdwWVYzSmxjRlEzVDBzMVoyUXpiR3gzVkRGNmFXRjJMMEU5UFE9PSIsImlhdCI6Ik1qQXlOQzB3TWkwd01TQXdOam96T0Rvek1TQXJNREF3TUNCVlZFTT0iLCJzaWduYXR1cmUiOiJiWGZEM1orc2w2OFZrcDJER05McjJEcElKWE5scVVpNmdPQjdobSs4WElWWlhCNjBkSkxvK25JQ1ExdmxEaFRuRWdxSnVZS2Uvb1kvUGk3cjdyWEFQclpFQ3BQTUt0NkhDaFhuMjVPaGlxU3h4WjdXMzBWOFZvSndXRi9OSXpCZVd5cHJEMmliNDBVVHdISkxDKzlXMk5IbWlTbys3b2F5cVN5MW12WHhWdjE2N2hXMFBkOVllWUpQZXMvM1dONGpPS0tnbHZWMkl2NnRaelhoUkRIaGhEYUViNmE2Tmh4a1hDcWswMHZtbm9DSkVsQnkzV1Y3SGY3eHBUZXcwdWhUNTkwMkRZZFVLaVA5Z0NGNmpKczVHdTRJR0w1RHlJN21VdmVuLzhYV0xEZmZ5WUlGZ1ZnMWVWR21LdzgvR2NVSFlxWWdyR2syQjFVY1hmeG95dVNDS1V4Uzg2UEF3TkZVL0g2cVN1T3BZNXJtTjRzbjRRM0pqa00xTlg2OU9OVXhpbnFQaXpCZ0VPZDFtb1pCczRpMWxRNUNlbEVRL3NYb2dQZ1hrODdSb2pVY2loaTVNUWs1M3B5VjRndFF6ZHo2VWJtMDhPQjhLLzNkWFdsMk5zVEMyYytKbzZGQ3orb1pXcFdSN0M3QXhPc1AxVnV1MHpmdCtOVElnNC9hQlZOciJ9LCJhdHRlc3Rlcl90Y2Jfc3RhdHVzIjoiVXBUb0RhdGUiLCJhdHRlc3Rlcl90Y2JfZGF0ZSI6IjIwMjMtMDgtMDlUMDA6MDA6MDBaIiwiYXR0ZXN0ZXJfdHlwZSI6IlREWCIsInZlcmlmaWVyX2luc3RhbmNlX2lkcyI6WyIwNTFhOTFiMS0zMWNkLTQxY2UtODM5MC02YmY4NDRiMWMzYzYiLCI5ZGZmYTI4NS1hMTJhLTQ3YzktYWIwYi05ZjAwODdlODAyNzQiLCIyZTcyNmM1MS1lNTFlLTRlZTAtOWVmOC0yODFmZWJkMmNkN2UiXSwiZGJnc3RhdCI6ImRpc2FibGVkIiwiZWF0X3Byb2ZpbGUiOiJodHRwczovL3BvcnRhbC5waWxvdC50cnVzdGF1dGhvcml0eS5pbnRlbC5jb20vZWF0X3Byb2ZpbGUuaHRtbCIsImludHVzZSI6ImdlbmVyaWMiLCJ2ZXIiOiIxLjAuMCIsImV4cCI6MTcwNjc2OTgxMSwianRpIjoiMDc0OGMxMDUtNGU3NS00MjMzLWFjMTktMDA0ZmVmNjMyMTZjIiwiaWF0IjoxNzA2NzY5NTExLCJpc3MiOiJJbnRlbCBUcnVzdCBBdXRob3JpdHkiLCJuYmYiOjE3MDY3Njk1MTF9.Zbx7bC3T2ix6lJSmTUbyAtX9d_tF_tUBCQM-bY8h8j9QSLYKgyUp8MWH0OQ1P4CZQldgyk6Sf0HjtZyuDlLZb-rgn-LaHG-xHdjkFcPEg_REmnzoBzLxDaKRyWjiJtuPWqi7pAEA998fpN6z06HF4t6gpLVCkMVNv_LBRdy1SmVN9VAuwZYBbMmM6j0EZ7XCIK5PqlmWua61dE-lx0UX17Bf9-BJUlE33nc0Hd0P51Tdgzz-klRzhcLYl3wEWxXuz4GXyEolQwTTVWU11dkYKPu13ZzQqsuXj5wZKuljKvQ-7tYA22TsGjIM-VUP6LfMOdPRV8zW_jpTPuNVMS97vuS1kjVGgazoZRUCn4P4vCZmlxZKJ1lJsO_aft8MZ2pFJTyAugxO1rkDZ9_fxgTiLTsCOyT8dRkpf3QFGwuBXNMV7vghdn4_sjlMBNvjyYmVD0_4vFogqxbbMw4n4b_22j4OlbUZBmFWsOyv4gY3WQjzAqztxFZ60RwTkLqK7YaY"
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
