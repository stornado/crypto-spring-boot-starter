package com.zxytech.crypto.starter.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import lombok.ToString;

@Data
@ToString
public class Request<T> {

    private T data;

    private String encrypt;
    @JsonProperty("ts")
    private Long timestamp;
    @JsonProperty("nc")
    private String nonce;
    private String sign;
}
