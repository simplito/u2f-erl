-module(u2f_tests).

-compile(export_all).

registration_test() -> 
    RegistrationRequest = u2f:json_decode(<<"{\"registerRequests\":[{\"version\":\"U2F_V2\",\"challenge\":\"XVgVPhdqSAb4WmAuD1VyUOtHB0_ruXYimSKFd24z-A4\"}],\"appId\":\"https://demo.yubico.com\"}">>),

    RegistrationResponse = u2f:json_decode(<<"{\"version\":\"U2F_V2\",\"registrationData\":\"BQSxO8VPngNl6Fh7mP1Q2NDDyuJ4GC9oBpY8SpL0Pb_FC6MH1uykEhsJTCTLXjgqc3WxhDcg0kf2NN2AxRTtj_K6QIGubiY1A5LQ1FRk1FrHNTNePZO-PP8lE7ckeY9rJzoJUkuJOgR3Gq0jjgqo5vv_WnO7cpBmJFvCZ1amuiBzIP0wggFdMIIBA6ADAgECAgEhMAoGCCqGSM49BAMCMCcxJTAjBgNVBAMMHExlZGdlciBGSURPIEF0dGVzdGF0aW9uIENBIDEwHhcNMTYwNzIxMTMzNjM3WhcNMjYwNzA5MTMzNjM3WjAwMS4wLAYDVQQDDCVMZWRnZXIgTmFuby1TIFUyRiBBdHRlc3RhdGlvbiBCYXRjaCAxMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEI8J_LIn2QsqirK_YkUx6ptPiwEs3El32mhaGcljsQEYwmAv4nEMs5onv7ARvWlz0YdAjNaCDhJh4YOH81wzTh6MXMBUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwCgYIKoZIzj0EAwIDSAAwRQIgehonosveKXiCa-D9vUyoXj9uP3JBfFlo26lAfmDEahQCIQCPKv96_v9Vz4_O1_V5z-ych5QKpUQlYMbnnz2gGqpqQjBFAiEAxzrWkO3vm4WNEWDVkckNtmJNLb_FMzmxV5Mc0R6gT7ICIG3FGR1AysSKece8zlrTUAhc-Hry9bJTkZCRPdBdc1hC\",\"clientData\":\"eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZmluaXNoRW5yb2xsbWVudCIsImNoYWxsZW5nZSI6IlhWZ1ZQaGRxU0FiNFdtQXVEMVZ5VU90SEIwX3J1WFlpbVNLRmQyNHotQTQiLCJvcmlnaW4iOiJodHRwczovL2RlbW8ueXViaWNvLmNvbSIsImNpZF9wdWJrZXkiOiJ1bnVzZWQifQ\"}">>),

    u2f:register(RegistrationRequest, RegistrationResponse),
    ok.

authentication_test() ->
    SignRequest = u2f:json_decode(<<"{\"registeredKeys\":[{\"version\":\"U2F_V2\",\"keyHandle\":\"ga5uJjUDktDUVGTUWsc1M149k748_yUTtyR5j2snOglSS4k6BHcarSOOCqjm-_9ac7tykGYkW8JnVqa6IHMg_Q\"}],\"challenge\":\"XVgVPhdqSAb4WmAuD1VyUOtHB0_ruXYimSKFd24z-A4\",\"appId\":\"https://demo.yubico.com\"}">>),

    SignResponse = u2f:json_decode(<<"{\"signatureData\":\"AQAAAAkwRQIhAP_idsoM-NeQKAfzq6be7IdBncgoqgzQV9x3DP0kFLr_AiALE0AdNHpE9mazqN4AneMZQQyvAX05Zyemshg9NS-U7w\",\"keyHandle\":\"ga5uJjUDktDUVGTUWsc1M149k748_yUTtyR5j2snOglSS4k6BHcarSOOCqjm-_9ac7tykGYkW8JnVqa6IHMg_Q\",\"clientData\":\"eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZ2V0QXNzZXJ0aW9uIiwiY2hhbGxlbmdlIjoiWFZnVlBoZHFTQWI0V21BdUQxVnlVT3RIQjBfcnVYWWltU0tGZDI0ei1BNCIsIm9yaWdpbiI6Imh0dHBzOi8vZGVtby55dWJpY28uY29tIiwiY2lkX3B1YmtleSI6InVudXNlZCJ9\"}">>),

    Registration = u2f:json_decode(<<"{\"publicKey\":\"BLE7xU-eA2XoWHuY_VDY0MPK4ngYL2gGljxKkvQ9v8ULowfW7KQSGwlMJMteOCpzdbGENyDSR_Y03YDFFO2P8ro\",\"keyHandle\":\"ga5uJjUDktDUVGTUWsc1M149k748_yUTtyR5j2snOglSS4k6BHcarSOOCqjm-_9ac7tykGYkW8JnVqa6IHMg_Q\",\"enrollmentTime\":1508766868892,\"counter\":-1,\"attestationCertificate\":\"MIIBXTCCAQOgAwIBAgIBITAKBggqhkjOPQQDAjAnMSUwIwYDVQQDDBxMZWRnZXIgRklETyBBdHRlc3RhdGlvbiBDQSAxMB4XDTE2MDcyMTEzMzYzN1oXDTI2MDcwOTEzMzYzN1owMDEuMCwGA1UEAwwlTGVkZ2VyIE5hbm8tUyBVMkYgQXR0ZXN0YXRpb24gQmF0Y2ggMTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCPCfyyJ9kLKoqyv2JFMeqbT4sBLNxJd9poWhnJY7EBGMJgL-JxDLOaJ7-wEb1pc9GHQIzWgg4SYeGDh_NcM04ejFzAVMBMGCysGAQQBguUcAgEBBAQDAgUgMAoGCCqGSM49BAMCA0gAMEUCIHoaJ6LL3il4gmvg_b1MqF4_bj9yQXxZaNupQH5gxGoUAiEAjyr_ev7_Vc-Pztf1ec_snIeUCqVEJWDG5589oBqqakI\"}">>),

    u2f:authenticate(SignRequest, SignResponse, Registration).

