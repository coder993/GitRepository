package com.hnykx.aesdemo;

import org.junit.Test;

public class AESTest {
    @Test
    public void main() throws Exception {
        // AES加密密码
        String password = "1234567";
        // 私钥
        String privateKey = "MIIBUwIBADANBgkqhkiG9w0BAQEFAASCAT0wggE5AgEAAkEAgXg8hdLqLGRUTatd2Iv1O+A2TKwEjFb36QFE4QWwOdL/1zvq1oCo7DzCJ2vUx3dj8BtqWxpmMtVeLALEpvijUQIDAQABAkAxzgoiROe2mgXgNwsL8ZMuLGtXBVlej1og9U8E7UZEh7zTLh2wUOkq1Q5KaKP8+MZz4AUwLQjZY176AeZ6EVx9AiEAy83j6R+4xYLk8pz/yaviv9RxGJk5GCGqI4b6qX4PEysCIQCioLbo+9/txYBLbbdvXXQ2zPRdJgJlxecpPxqklqGVcwIgaKivrIzsvwkL94cmV/Nb+zTma0JsLndDPwFXAelJZocCIH3eC5MpFnhtys0WXsnXt9GOMXdCqspgMHhQ+er3FpqXAiB4c6biAepYaylwgQT3/Nyu1MHQ5Ord44yawNYnlA1uEw==";
        // 公钥
        String publicKey = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAIF4PIXS6ixkVE2rXdiL9TvgNkysBIxW9+kBROEFsDnS/9c76taAqOw8widr1Md3Y/AbalsaZjLVXiwCxKb4o1ECAwEAAQ==";
        // RSA加密AES密码
        String rsacontent = RSACoder.encryptByPrivateKey(password, privateKey);
        System.out.println("RSA加密后的AES密码：" + rsacontent);
        // 待加密数据
        String strParam = "";
        // 加密后的数据
        String aesParam = AESUtil.encrypt(strParam, rsacontent);
        System.out.println("加密后数据：" + aesParam);
        System.out.println("---↑加密---------------------↓解密---");
        // 待解密数据
        String stringParam = "";
        // 解密后的数据
        String resParam = AESUtil.decrypt(stringParam, rsacontent);
        System.out.println("解密后数据" + resParam);

    }
}
