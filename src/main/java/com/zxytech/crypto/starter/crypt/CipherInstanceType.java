package com.zxytech.crypto.starter.crypt;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum CipherInstanceType {
    AES_CBC_NOPADDING("AES/CBC/NoPadding"),
    AES_CBC_PKCS5PADDING("AES/CBC/PKCS5Padding"),
    AES_ECB_NOPADDING("AES/ECB/NoPadding"),
    AES_ECB_PKCS5PADDING("AES/ECB/PKCS5Padding"),
    AES_GCM_NOPADDING("AES/GCM/NoPadding"),
    DESEDE_CBC_NOPADDING("DESede/CBC/NoPadding"),
    DESEDE_CBC_PKCS5PADDING("DESede/CBC/PKCS5Padding"),
    DESEDE_ECB_NOPADDING("DESede/ECB/NoPadding"),
    DESEDE_ECB_PKCS5PADDING("DESede/ECB/PKCS5Padding"),
    RSA_ECB_PKCS1PADDING("RSA/ECB/PKCS1Padding"),
    RSA_ECB_OAEPWITHSHA_1ANDMGF1PADDING("RSA/ECB/OAEPWithSHA-1AndMGF1Padding"),
    RSA_ECB_OAEPWITHSHA_256ANDMGF1PADDING("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");

    String value;
}
