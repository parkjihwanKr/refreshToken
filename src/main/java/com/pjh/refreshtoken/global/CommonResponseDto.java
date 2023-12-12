package com.pjh.refreshtoken.global;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@JsonInclude(JsonInclude.Include.NON_NULL) // null이 아닌 필드만 JSON에 포함
public class CommonResponseDto<T> {
    private String msg;
    private int statusCode;
    private T data;

    public CommonResponseDto(String msg, int statusCode, T data){
        this.msg = msg;
        this.statusCode = statusCode;
        this.data = data;
    }

    public CommonResponseDto(String msg, int statusCode){
        this.msg = msg;
        this.statusCode = statusCode;
        this.data = null;
    }
}
