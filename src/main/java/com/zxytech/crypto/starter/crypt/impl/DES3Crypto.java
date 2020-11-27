package com.zxytech.crypto.starter.crypt.impl;

import com.zxytech.crypto.starter.crypt.CipherInstanceType;
import com.zxytech.crypto.starter.crypt.Crypto;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class DES3Crypto implements Crypto {

    private String key;

    public DES3Crypto(String key) {
        this.key = key;
    }

    @Override
    public byte[] decrypt(byte[] data) {
        try {
            Cipher cipher = Cipher
                .getInstance(CipherInstanceType.DESEDE_ECB_PKCS5PADDING.getValue());
            SecretKey sckey = new SecretKeySpec(key.getBytes(), "DESede");
            IvParameterSpec iv = new IvParameterSpec(key.getBytes());
            cipher.init(Cipher.DECRYPT_MODE, sckey, iv);
            return cipher.doFinal(data);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            log.error("DES3 decrypt failed", e);
        }
        return new byte[0];
    }

    @Override
    public byte[] encrypt(byte[] data) {
        try {
            Cipher cipher = Cipher
                .getInstance(CipherInstanceType.DESEDE_ECB_PKCS5PADDING.getValue());
            SecretKey sckey = new SecretKeySpec(key.getBytes(), "DESede");
            IvParameterSpec iv = new IvParameterSpec(key.getBytes());
            cipher.init(Cipher.ENCRYPT_MODE, sckey, iv);
            return cipher.doFinal(data);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            log.error("DES3 decrypt failed", e);
        }
        return new byte[0];
    }

}
