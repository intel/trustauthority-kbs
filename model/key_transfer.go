/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package model

import (
	itaConnector "github.com/intel/trustauthority-client/go-connector"
)

type KeyTransferRequest struct {
	// Describes the Signed JWT Token received from the workload
	// example: eyJhbGciOiJQUzM4NCIsImprdSI6Imh0dHBzOi8vd3d3LmludGVsLmNvbS9hbWJlci9jZXJ0cyIsImtpZCI6IjNjMjQxOGI1ZTY5ZTI2NDRiOTE2NzJmZjYwNTY2NjRkOTI0MjM0ZjAiLCJ0eXAiOiJKV1QifQ.eyJhbWJlcl90cnVzdF9zY29yZSI6MTAsImFtYmVyX3JlcG9ydF9kYXRhIjoiZWZmNWEyYTExNDg2N2FhOTQ0NjIwYzQ4Y2Q4NjcwNDZkYmY2ZjdmY2JmODQ5YTliNjZhNzg3MjJmNGRjZDdjOTAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAiLCJhbWJlcl90ZWVfaGVsZF9kYXRhIjoiQVFBQkFLMkxyUDhSZ1ROMW5naFJZWTBKQnZZQ1M3K2JCcVhoRjIzY2JkVFVRR3F3MEl2Wm9NYkpySUNmQXJ1MjVWWWpKbkZaS0Vvb1hRWmhPZUlBeTZNV0RpWEpmdDc0VnVUR25YZnNLUDk4bWNvZXBiQ2M4U1BJRFBsdkhTQy9QQWtlRzJUdlZ3QkhBbjcvcURVNXJwUENIS05xWDYweUd2SW95QjhrLzBJTzR5M2V0ekdvQjF5YVRPQ3Iyd1NCYmdUUkV1M3ppY3JJODFPL1RsK0FaWitVekFCdUxSUEgxdlBrelBQYVhCT21IN2Q4SnZXZ0RwSjhFenBNRitzakt4dXI1dkEraDNjamxDUG4yZjFjODhqZGIyNDgyUUJ2STZoanB4R2k0dWRUVVdJekdKdElKeElUbnNscThwTFpUekhnR3V2UEdYK2xkYWFKdUVPSGJBeFhDRW4zTnNGNHZvVjFSQ2I1OXBBMEI2NnZBd1RHZmFONE9pR205aGhiTk1NTnZNeGlhZmdGanJWWHpjc1BvUE5vN2hPd0dMcVJFdGUrMWkzZzlGNDBCK2hEZVV6elZhTU8zVkxHTUtEcDlUSDJqMytYSnRnU3p4dThOWlg1WEZVeGpSMlJINzV5d25vbnRNQStnaDZid1d1UUlWWWI2K0k3eHEzdWxOaUZldzZ4eWc9PSIsImFtYmVyX3NneF9tcmVuY2xhdmUiOiI4M2Y0ZTgxOTg2MWFkZWY2ZmZiMmE0ODY1ZWZlYTkzMzdiOTFlZDMwZmEzMzQ5MWIxN2YwZDVkOWU4MjA0NDEwIiwiYW1iZXJfc2d4X2lzX2RlYnVnZ2FibGUiOmZhbHNlLCJhbWJlcl9zZ3hfbXJzaWduZXIiOiI4M2Q3MTllNzdkZWFjYTE0NzBmNmJhZjYyYTRkNzc0MzAzYzg5OWRiNjkwMjBmOWM3MGVlMWRmYzA4YzdjZTllIiwiYW1iZXJfc2d4X2lzdnByb2RpZCI6MCwiYW1iZXJfc2d4X2lzdnN2biI6MCwiYW1iZXJfbWF0Y2hlZF9wb2xpY3lfaWRzIjpbImY0MzZjMzBhLTY0NGUtNGJiMi1iMzJjLTFmNWJmZjc3NTJmMiJdLCJhbWJlci1mYWl0aGZ1bC1zZXJ2aWNlLWlkcyI6WyI2YmFhNjMwMS0zMWVlLTQ1NmMtOWEzOC1lMjc5YWM3ZjZkNmEiLCJkZTU3NDU5ZC1mYjU2LTRhODgtYmU1ZC02ZjJhMzcwMzkzOWMiXSwiYW1iZXJfdGNiX3N0YXR1cyI6Ik9LIiwiYW1iZXJfZXZpZGVuY2VfdHlwZSI6IlNHWCIsImFtYmVyX3NpZ25lZF9ub25jZSI6dHJ1ZSwiYW1iZXJfY3VzdG9tX3BvbGljeSI6e30sInZlciI6IjEuMCIsImV4cCI6MTY2NDQ0NzA5MywianRpIjoiMzc5ZjBiMDctNTUzNy00YzdhLWFlNTAtODk2YTU1ZjIzNzY2IiwiaWF0IjoxNjY0NDQ2NzYzLCJpc3MiOiJBUyBBdHRlc3RhdGlvbiBUb2tlbiBJc3N1ZXIifQ.X2UDvraRVzAJpC1G1WAK2Qbx64d9WI5T_AKAq1lK5VAjEf409y5fZPxkBdZ-fGYt653nQ5Ah0-jkFRt0Yo7B2cxNmDWn61mMW9yYtt_55qHcbuDX5x4a-7MVawWjS1gLzY7qddmpzoIhwrx575c5JoQjG4qybDejRufUxhvu_XOOxSfhyh4JGRxBYNX19ZGeIbHtE3mfAXqg6qphZFfClIQLdlU-wGbefyN5mwpTK0T3eQ9Tlt0zZFrcv7lNIAPHHB52Ke9R7qdFEoVNNX-8YFMzk4gQyZdzYJS7Q3ElhQYXhBWnY5iwquftQztQcfydJL8o1OC-Ru0s-keF7OBaxABHcv5OhUKlVc44zaBnekP9lTzRCINYnVK67KxyAHsgXkK19UiX6v1FYxdcmdwZgNn5OkCwxiAMLgB8_CQku6q4aeyhCMo4acD1xKd6kkfgYQDxehLbGV6weT4E60omx6UFE13L9yANNNoWtzy0A4PJsiw0tbRPYYO8ehZ8Vgrb9sc00cdqG7_7ok-iivuxklaaSuzrY8VtkGw9T8g0w__fJ0X2KCMPcl3XfNidhOGxJ9402ff93X-QY3dHyaLOqmtJK0vlQ0vuoThseBSOezETalhFCuh-JUYZskokQ21fDPs2xDiytKubxqzrJVF1G1n1AVNWlIZXPXLyoXANS4s
	AttestationToken string `json:"attestation_token,omitempty"`
	// SGX\TDX Quote to be attested
	// example: AwACAAAAAAAHAAwAk5pyM/ecTKmUCg2zlX8GBxdZqc7ZHvph1dB/Gx0CGGUAAAAABQUMDP//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABQAAAAAAAADnAAAAAAAAADi4Dt0xe3/egf97SCWPr8ncgUiYi9E4SNLWlL0C5rHTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADUEqTwfvg4kqWRX7KrWEvjHhhuWk+Vq19pUP1OuGlNewAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACK0eSGrg5DJjzLRoYjBDpov80TukNTvbsNjnfQy6Ui/wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAxBAAAA6Yv94bEfYZ0eRjJtx6A5uPehGmdrMCDRHqKDzeKEePZbfVaLvmUS7rCn8SB5trPOA1R8df9nXk2jQ8aRQc6hnmiYobB5ujL44dQWqgg67mqFjIPmJsV0D+nlJMLGwBYnZZklCfDQ+82rFoExN3805BSWUvhkqaAChIJqkvIQfzBQUMDP//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFQAAAAAAAADnAAAAAAAAAK4SPL+pbCaFYN/V3/5IVM5EPeTg+lHSgRhMlCjXo0D7AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACMT1d115ZQPpYTf3fGioKaAFasje1wFAsIGwlEkMV7/wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEABwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACjlJOfr4vl+VcNZYWRGfPkCTKi8Upz0gXEsoFD19ltXQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+1txjKVJ2JdwfOtnwK2QGXS/dL3xLnR0/UPemPHtPUYTxNIQi/CLW5lIANsuPt9K0gr2RsuHnO7TUUjSOVCHGiAAAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8FAFwOAAAtLS0tLUJFR0lOIENFUlRJRklDQVRFLS0tLS0KTUlJRTh6Q0NCSm1nQXdJQkFnSVZBTGNPM1VWbHRVNnZOL1RTc2liUmcxM0U2c2NkTUFvR0NDcUdTTTQ5QkFNQ01IQXhJakFnQmdOVgpCQU1NR1VsdWRHVnNJRk5IV0NCUVEwc2dVR3hoZEdadmNtMGdRMEV4R2pBWUJnTlZCQW9NRVVsdWRHVnNJRU52Y25CdmNtRjBhVzl1Ck1SUXdFZ1lEVlFRSERBdFRZVzUwWVNCRGJHRnlZVEVMTUFrR0ExVUVDQXdDUTBFeEN6QUpCZ05WQkFZVEFsVlRNQjRYRFRJeU1ETXkKTlRFMU5UVTBObG9YRFRJNU1ETXlOVEUxTlRVME5sb3djREVpTUNBR0ExVUVBd3daU1c1MFpXd2dVMGRZSUZCRFN5QkRaWEowYVdacApZMkYwWlRFYU1CZ0dBMVVFQ2d3UlNXNTBaV3dnUTI5eWNHOXlZWFJwYjI0eEZEQVNCZ05WQkFjTUMxTmhiblJoSUVOc1lYSmhNUXN3CkNRWURWUVFJREFKRFFURUxNQWtHQTFVRUJoTUNWVk13V1RBVEJnY3Foa2pPUFFJQkJnZ3Foa2pPUFFNQkJ3TkNBQVNBbWg4Uy93cU4Kd2wybUt1UzVmaXM1eVlvdWNwZXZTUEVhTHdYem9hdUhnWDgwTDZpYVhpbW9WYXFRZURoQ2o0dThqQTV5OEFOenJOQ0UwTUhybDgzSgpvNElERGpDQ0F3b3dId1lEVlIwakJCZ3dGb0FVbFc5ZHpiMGI0ZWxBU2NuVTlEUE9BVmNMM2xRd2F3WURWUjBmQkdRd1lqQmdvRjZnClhJWmFhSFIwY0hNNkx5OWhjR2t1ZEhKMWMzUmxaSE5sY25acFkyVnpMbWx1ZEdWc0xtTnZiUzl6WjNndlkyVnlkR2xtYVdOaGRHbHYKYmk5Mk15OXdZMnRqY213L1kyRTljR3hoZEdadmNtMG1aVzVqYjJScGJtYzlaR1Z5TUIwR0ExVWREZ1FXQkJTR1U3WkRXbnpOQmhtMwpPV0RqYnZQMXIyUDhIakFPQmdOVkhROEJBZjhFQkFNQ0JzQXdEQVlEVlIwVEFRSC9CQUl3QURDQ0Fqc0dDU3FHU0liNFRRRU5BUVNDCkFpd3dnZ0lvTUI0R0NpcUdTSWI0VFFFTkFRRUVFUEVPeFZJYkNvSFV6ZTV4QVU2MUdSSXdnZ0ZsQmdvcWhraUcrRTBCRFFFQ01JSUIKVlRBUUJnc3Foa2lHK0UwQkRRRUNBUUlCQkRBUUJnc3Foa2lHK0UwQkRRRUNBZ0lCQkRBUUJnc3Foa2lHK0UwQkRRRUNBd0lCQXpBUQpCZ3NxaGtpRytFMEJEUUVDQkFJQkF6QVJCZ3NxaGtpRytFMEJEUUVDQlFJQ0FQOHdFUVlMS29aSWh2aE5BUTBCQWdZQ0FnRC9NQkFHCkN5cUdTSWI0VFFFTkFRSUhBZ0VBTUJBR0N5cUdTSWI0VFFFTkFRSUlBZ0VBTUJBR0N5cUdTSWI0VFFFTkFRSUpBZ0VBTUJBR0N5cUcKU0liNFRRRU5BUUlLQWdFQU1CQUdDeXFHU0liNFRRRU5BUUlMQWdFQU1CQUdDeXFHU0liNFRRRU5BUUlNQWdFQU1CQUdDeXFHU0liNApUUUVOQVFJTkFnRUFNQkFHQ3lxR1NJYjRUUUVOQVFJT0FnRUFNQkFHQ3lxR1NJYjRUUUVOQVFJUEFnRUFNQkFHQ3lxR1NJYjRUUUVOCkFRSVFBZ0VBTUJBR0N5cUdTSWI0VFFFTkFRSVJBZ0VMTUI4R0N5cUdTSWI0VFFFTkFRSVNCQkFFQkFNRC8vOEFBQUFBQUFBQUFBQUEKTUJBR0NpcUdTSWI0VFFFTkFRTUVBZ0FBTUJRR0NpcUdTSWI0VFFFTkFRUUVCakJnYWdBQUFEQVBCZ29xaGtpRytFMEJEUUVGQ2dFQgpNQjRHQ2lxR1NJYjRUUUVOQVFZRUVHV08wU2lPdHBGbDI0ZEZtT3lPVUs0d1JBWUtLb1pJaHZoTkFRMEJCekEyTUJBR0N5cUdTSWI0ClRRRU5BUWNCQVFIL01CQUdDeXFHU0liNFRRRU5BUWNDQVFFQU1CQUdDeXFHU0liNFRRRU5BUWNEQVFIL01Bb0dDQ3FHU000OUJBTUMKQTBnQU1FVUNJRGxqWDRBeDdTNDE1TEdjZG04czRucG14NU9zak4yMkFNMC9XV2hBY2MrdEFpRUE2M3N6ckJaWjZDUUI5ckFwZ3NHSgpMazVNQUVWZ1lwZ3J0blFoYmFxZytQTT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLS0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLQpNSUlDbGpDQ0FqMmdBd0lCQWdJVkFKVnZYYzI5RytIcFFFbkoxUFF6emdGWEM5NVVNQW9HQ0NxR1NNNDlCQU1DCk1HZ3hHakFZQmdOVkJBTU1FVWx1ZEdWc0lGTkhXQ0JTYjI5MElFTkJNUm93R0FZRFZRUUtEQkZKYm5SbGJDQkQKYjNKd2IzSmhkR2x2YmpFVU1CSUdBMVVFQnd3TFUyRnVkR0VnUTJ4aGNtRXhDekFKQmdOVkJBZ01Ba05CTVFzdwpDUVlEVlFRR0V3SlZVekFlRncweE9EQTFNakV4TURVd01UQmFGdzB6TXpBMU1qRXhNRFV3TVRCYU1IQXhJakFnCkJnTlZCQU1NR1VsdWRHVnNJRk5IV0NCUVEwc2dVR3hoZEdadmNtMGdRMEV4R2pBWUJnTlZCQW9NRVVsdWRHVnMKSUVOdmNuQnZjbUYwYVc5dU1SUXdFZ1lEVlFRSERBdFRZVzUwWVNCRGJHRnlZVEVMTUFrR0ExVUVDQXdDUTBFeApDekFKQmdOVkJBWVRBbFZUTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFTlNCLzd0MjFsWFNPCjJDdXpweHc3NGVKQjcyRXlER2dXNXJYQ3R4MnRWVExxNmhLazZ6K1VpUlpDbnFSN3BzT3ZncUZlU3hsbVRsSmwKZVRtaTJXWXozcU9CdXpDQnVEQWZCZ05WSFNNRUdEQVdnQlFpWlF6V1dwMDBpZk9EdEpWU3YxQWJPU2NHckRCUwpCZ05WSFI4RVN6QkpNRWVnUmFCRGhrRm9kSFJ3Y3pvdkwyTmxjblJwWm1sallYUmxjeTUwY25WemRHVmtjMlZ5CmRtbGpaWE11YVc1MFpXd3VZMjl0TDBsdWRHVnNVMGRZVW05dmRFTkJMbVJsY2pBZEJnTlZIUTRFRmdRVWxXOWQKemIwYjRlbEFTY25VOURQT0FWY0wzbFF3RGdZRFZSMFBBUUgvQkFRREFnRUdNQklHQTFVZEV3RUIvd1FJTUFZQgpBZjhDQVFBd0NnWUlLb1pJemowRUF3SURSd0F3UkFJZ1hzVmtpMHcraTZWWUdXM1VGLzIydWFYZTBZSkRqMVVlCm5BK1RqRDFhaTVjQ0lDWWIxU0FtRDV4a2ZUVnB2bzRVb3lpU1l4ckRXTG1VUjRDSTlOS3lmUE4rCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNqekNDQWpTZ0F3SUJBZ0lVSW1VTTFscWROSW56ZzdTVlVyOVFHemtuQnF3d0NnWUlLb1pJemowRUF3SXcKYURFYU1CZ0dBMVVFQXd3UlNXNTBaV3dnVTBkWUlGSnZiM1FnUTBFeEdqQVlCZ05WQkFvTUVVbHVkR1ZzSUVOdgpjbkJ2Y21GMGFXOXVNUlF3RWdZRFZRUUhEQXRUWVc1MFlTQkRiR0Z5WVRFTE1Ba0dBMVVFQ0F3Q1EwRXhDekFKCkJnTlZCQVlUQWxWVE1CNFhEVEU0TURVeU1URXdORFV4TUZvWERUUTVNVEl6TVRJek5UazFPVm93YURFYU1CZ0cKQTFVRUF3d1JTVzUwWld3Z1UwZFlJRkp2YjNRZ1EwRXhHakFZQmdOVkJBb01FVWx1ZEdWc0lFTnZjbkJ2Y21GMAphVzl1TVJRd0VnWURWUVFIREF0VFlXNTBZU0JEYkdGeVlURUxNQWtHQTFVRUNBd0NRMEV4Q3pBSkJnTlZCQVlUCkFsVlRNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVDNm5Fd01ESVlaT2ovaVBXc0N6YUVLaTcKMU9pT1NMUkZoV0dqYm5CVkpmVm5rWTR1M0lqa0RZWUwwTXhPNG1xc3lZamxCYWxUVll4RlAyc0pCSzV6bEtPQgp1ekNCdURBZkJnTlZIU01FR0RBV2dCUWlaUXpXV3AwMGlmT0R0SlZTdjFBYk9TY0dyREJTQmdOVkhSOEVTekJKCk1FZWdSYUJEaGtGb2RIUndjem92TDJObGNuUnBabWxqWVhSbGN5NTBjblZ6ZEdWa2MyVnlkbWxqWlhNdWFXNTAKWld3dVkyOXRMMGx1ZEdWc1UwZFlVbTl2ZEVOQkxtUmxjakFkQmdOVkhRNEVGZ1FVSW1VTTFscWROSW56ZzdTVgpVcjlRR3prbkJxd3dEZ1lEVlIwUEFRSC9CQVFEQWdFR01CSUdBMVVkRXdFQi93UUlNQVlCQWY4Q0FRRXdDZ1lJCktvWkl6ajBFQXdJRFNRQXdSZ0loQU9XLzVRa1IrUzlDaVNEY05vb3dMdVBSTHNXR2YvWWk3R1NYOTRCZ3dUd2cKQWlFQTRKMGxySG9NcytYbzVvL3NYNk85UVd4SFJBdlpVR09kUlE3Y3ZxUlhhcUk9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K
	Quote []byte `json:"quote,omitempty"`
	// Signed entity containing a base64 encoded randomized 64 bytes, issued at timestamp and signature.
	// example: { "val": "YKrm2nC9bZQLstn+ABSP6LCu4TcyU3evGx+Cc1uRRkqoq4Vf6qyQNlnNIs/BpiKs/ZWYV73xxexFU+O4PRzUXQ==", "iat": "MjAyMi0wNy0wNSAwOTozOToxOS4zNTEwNTM2NiArMDAwMCBVVEM=", "signature": "cipPzJ3Ar6QwBXJavzzIjNrH5wwuyUcDn28Wtfgzq2SBcMVTgsOVfCgqFocvS2OrwkKxNrZEna5ySoqdUg7FBQhfEPGY6zDGeiewIDUeklWdbzM8Ycpwh6u/VO2KDG74fA+Ozho/Itae1KpATce+f4g3J32Xpbp5UHM4W9HEQDtMW3XrMICDVi/bhZ5/qYbe4D2vde/ht7Nk+7rlzNYCVxaiiF1wMvWSdU+YwnToP+yJNTXBoqsiZoKvkbomvqrlbMd73/pmI7NGvcLGDHkCk7X6gDPsgk3EEiD7qvOT8YB4LyM+Vj/x005po7g/rUQscwpUQlrTkym7rY4lRyF6OqpRwEm3iRgsEr7SWdYS5KaFpY+hwpepAx3Pl2rbBOQpDc9ZJhW9xALACMHo87efD8iAIMSiXfUyW8NP4q+lfjA9ZMu10bRPNx+PSYHCvWcLm8QjU0HnUH+dIXtjxw9ujDwNSE37Ygqxgm2OstyR5Ysv0yid9QXKr4KsrJKVjnOk" }
	VerifierNonce *itaConnector.VerifierNonce `json:"nonce,omitempty"`
	// User data - enclave held data
	// example: uJzueTbG8uTrkoBcSG7Duu2izGJ2lAZveRqx0E/exGnX81/4kJdU1Wh1FDkn0K8+
	RuntimeData []byte `json:"user_data,omitempty"`
	// Log of all events that get extended to RTMRs (runtime-extendable measurement registers) . RTMR event log is available through ACPI.
	// example: [ { "rtmr": {  "index":1....
	EventLog []byte `json:"event_log,omitempty"`
}

type KeyTransferResponse struct {
	WrappedKey []byte `json:"wrapped_key"`
	WrappedSWK []byte `json:"wrapped_swk,omitempty"`
}
