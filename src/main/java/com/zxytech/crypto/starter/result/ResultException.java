package com.zxytech.crypto.starter.result;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.ToString;

@AllArgsConstructor
@Getter
@ToString
public class ResultException extends Exception {

    protected ResultStatus resultStatus;

    public ResultException() {
        this.resultStatus = ResultStatus.INTERNAL_SERVER_ERROR;
    }
}
