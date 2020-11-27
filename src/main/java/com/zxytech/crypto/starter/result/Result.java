package com.zxytech.crypto.starter.result;


import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zxytech.crypto.starter.crypt.Crypto;
import java.util.Base64;
import lombok.Getter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.util.DigestUtils;

@Slf4j
@Getter
@ToString
public class Result<T> {

    /**
     * 业务错误码
     */
    private Integer code;
    /**
     * 信息描述
     */
    @JsonProperty("msg")
    private String message;
    /**
     * 返回参数
     */
//    @JsonIgnore
    private T data;
    /**
     * 返回加密报文
     */
    private String encrypt;

    @JsonProperty("ts")
    private Long timestamp;
    @JsonProperty("nc")
    private String nonce;
    private String sign;


    private Result(ResultStatus resultStatus, T data, Crypto crypto, String charset) {
        this.code = resultStatus.getCode();
        this.message = resultStatus.getMessage();
        this.data = data;
        ObjectMapper mapper = new ObjectMapper();
        try {
            this.encrypt = this.data == null ? "" : Base64.getEncoder()
                .encodeToString(crypto.encrypt(mapper.writeValueAsBytes(data)));
        } catch (JsonProcessingException e) {
            log.error("data is invalid json", e);
            this.encrypt = crypto.encrypt(data.toString(), charset);
        }

        this.timestamp = System.currentTimeMillis();
        this.nonce = RandomStringUtils.randomAlphanumeric(6);
        this.sign = DigestUtils.md5DigestAsHex(String
            .format("code=%d&msg=%s&ts=%d&nc=%s&encrypt=%s", this.code,
                this.message, this.timestamp, this.nonce, this.encrypt).getBytes());
    }

    /**
     * 业务成功返回业务代码和描述信息
     */
    public static Result<Void> success() {
        return new Result<Void>(ResultStatus.SUCCESS, null, null, null);
    }

    /**
     * 业务成功返回业务代码,描述和返回的参数
     */
    public static <T> Result<T> success(T data, Crypto crypto, String charset) {
        return new Result<T>(ResultStatus.SUCCESS, data, crypto, charset);
    }

    /**
     * 业务成功返回业务代码,描述和返回的参数
     */
    public static <T> Result<T> success(ResultStatus resultStatus, T data, Crypto crypto,
        String charset) {
        if (resultStatus == null) {
            return success(data, crypto, charset);
        }
        return new Result<T>(resultStatus, data, crypto, charset);
    }

    /**
     * 业务异常返回业务代码和描述信息
     */
    public static <T> Result<T> failure() {
        return new Result<T>(ResultStatus.INTERNAL_SERVER_ERROR, null, null, null);
    }

    /**
     * 业务异常返回业务代码,描述和返回的参数
     */
    public static <T> Result<T> failure(ResultStatus resultStatus) {
        return failure(resultStatus, null, null, null);
    }

    /**
     * 业务异常返回业务代码,描述和返回的参数
     */
    public static <T> Result<T> failure(ResultStatus resultStatus, T data, Crypto crypto,
        String charset) {
        if (resultStatus == null) {
            return new Result<T>(ResultStatus.INTERNAL_SERVER_ERROR, null, null, null);
        }
        return new Result<T>(resultStatus, data, crypto, charset);
    }
}

