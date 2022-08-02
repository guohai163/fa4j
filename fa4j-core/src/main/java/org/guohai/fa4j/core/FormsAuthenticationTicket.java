package org.guohai.fa4j.core;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

/**
 * 票据的数据类
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class FormsAuthenticationTicket {



    /**
     * 票据版本
     */
    private int version;
    /**
     * 票据名字
     */
    private String name;

    /**
     * 过期时间
     */
    private Date expiration;

    /**
     * 发布时间
     */
    private Date issueDate;

    /**
     * 是否固化
     */
    private boolean persistent;

    /**
     * 用户数据
     */
    private String userData;

    /**
     * cookies存储路径
     */
    private String cookiePath;
    /**
     * Unix 时间 1970-01-01 00:00:00 与 Win32 FileTime 时间 1601-01-01 00:00:00
     * 毫秒数差
     */
    private final static long UNIX_FILETIME_MILLISECOND_DIFF = 11644473600000L;

    /**
     * 1秒=1000毫秒(ms) 1秒=1,000,000 微秒(μs) 1秒=1,000,000,000 纳秒
     */

    /**
     * 获取 生成日期 .net 格式 的  utc时间
     * ticks计算是从 0001-01-01 00:00:00:000 到此的 100ns 计算。
     * 毫秒 * 10000 得到 100纳秒为单位
     * @return
     */
    long getIssueDateUtcTick(){

        return (issueDate.getTime()*10000)+621355968000000000L;
    }

    void setIssueDateUtcTick(long n){
        issueDate = new Date();
        issueDate.setTime((n-621355968000000000L)/10000);
    }

    /**
     * 获取 生成日期 .net格式的 file time 时间
     * @return 公元 1601 年 1 月 1 日午夜 12:00 之前的日期和时间
     */
    long getIssueDateUtcToFileTime(){
        return (issueDate.getTime()+UNIX_FILETIME_MILLISECOND_DIFF) * 10000;
    }



    void setIssueDateUtcFileTime(long n){
        issueDate = new Date(n/10000-UNIX_FILETIME_MILLISECOND_DIFF);
    }

    long getExpirationUtcTick(){
        return (expiration.getTime()*10000)+621355968000000000L;
    }
    long getExpirationUtcFileTime(){
        return (expiration.getTime()+UNIX_FILETIME_MILLISECOND_DIFF) * 10000;
    }

    void setExpirationUtcTick(long n){
        expiration = new Date();
        expiration.setTime((n-621355968000000000L)/10000);
    }

    void setExpirationUtcFileTime(long n){
        expiration= new Date(n/10000-UNIX_FILETIME_MILLISECOND_DIFF);

    }
}
