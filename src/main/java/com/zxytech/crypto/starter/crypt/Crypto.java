package com.zxytech.crypto.starter.crypt;


import java.io.UnsupportedEncodingException;
import java.util.Base64;
import org.springframework.beans.factory.annotation.Value;

public interface Crypto {

    @Value("${crypto.charset}")
    String charset = "UTF-8";

    default String decrypt(String data) {
        return decrypt(data, charset);
    }

    byte[] decrypt(byte[] data);

    default String decrypt(String data, String charset) {
        byte[] bytes = new byte[0];
        bytes = Base64.getDecoder().decode(data);
        //具体的解密实现
        byte[] decrypted = decrypt(bytes);
        try {
            return new String(decrypted, charset);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return null;
    }

    default String encrypt(String data) {
        return encrypt(data, charset);
    }

    byte[] encrypt(byte[] data);



    default String encrypt(String data, String charset) {
        try {
            byte[] bytes = data.getBytes(charset);
            byte[] encrypted = encrypt(bytes);
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return null;
    }
}
