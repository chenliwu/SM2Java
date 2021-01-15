package org.pzone.crypto;

import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Assert;
import org.junit.Test;
import sun.nio.cs.StandardCharsets;

import java.math.BigInteger;

public class TestSM2 {

    /**
     * 生成公钥和私钥
     */
    @Test
    public void generatePublicKeyAndPrimaryKey() {
        try {
            SM2 sm2 = new SM2();
            SM2KeyPair keyPair = sm2.generateKeyPair();
            ECPoint publicKey = keyPair.getPublicKey();
            BigInteger privateKey = keyPair.getPrivateKey();
            // 导出公钥
            sm2.exportPublicKey(publicKey, "d:/ssl/publickey.pem");
            // 导出私钥
            sm2.exportPrivateKey(privateKey, "d:/ssl/privatekey.pem");
        } catch (Exception e) {
            System.out.println("异常：" + e.getMessage());
            Assert.fail();
        }
    }

    @Test
    public void testImportPublicKeyAndPrimaryKey() {
        try {
            SM2 sm2 = new SM2();
            ECPoint publicKey = sm2.importPublicKey("d:/ssl/publickey.pem");
            Assert.assertNotNull(publicKey);
            BigInteger privateKey = sm2.importPrivateKey("d:/ssl/privatekey.pem");
            Assert.assertNotNull(privateKey);

            // 使用公钥加密
            String data = "密文....";
            byte[] encryptByteData = sm2.encrypt(data, publicKey);
            System.out.println("待加密数据: " + data);
            System.out.println("加密后的base64数据: " + Base64.toBase64String(encryptByteData));

            // 使用私钥解密
            String origin = sm2.decrypt(encryptByteData, privateKey);
            System.out.println("解密后的数据: " + origin);
        } catch (Exception e) {
            System.out.println("异常：" + e.getMessage());
            Assert.fail();
        }
    }


    @Test
    public void testSm2() {
        SM2 sm2 = new SM2();
        SM2KeyPair keys = sm2.generateKeyPair();
        ECPoint pubKey = keys.getPublicKey();
        BigInteger privKey = keys.getPrivateKey();
        byte[] data = sm2.encrypt("Hello World", pubKey);
        System.out.println("encrypt: " + data);
        String origin = sm2.decrypt(data, privKey);
        System.out.println("decrypt: " + origin);
    }
}
