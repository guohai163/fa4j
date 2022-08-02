package org.guohai.fa4j.core;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * 模拟 .net System.Web.Security 下的同名类
 * 对票据进行串行化，当前 版本1
 *
 */
public class FormsAuthenticationTicketSerializer {

    /**
     * Current (v1) ticket format
     * ==========================
     *
     * Serialized ticket format version number: 1 byte
     * FormsAuthenticationTicket.Version: 1 byte
     * FormsAuthenticationTicket.IssueDateUtc: 8 bytes
     * {spacer}: 1 byte
     * FormsAuthenticationTicket.ExpirationUtc: 8 bytes
     * FormsAuthenticationTicket.IsPersistent: 1 byte
     * FormsAuthenticationTicket.Name: 1+ bytes (1+ length prefix, 0+ payload)
     * FormsAuthenticationTicket.UserData: 1+ bytes (1+ length prefix, 0+ payload)
     * FormsAuthenticationTicket.CookiePath: 1+ bytes (1+ length prefix, 0+ payload)
     * {footer}: 1 byte
     */
    private static final byte CURRENT_TICKET_SERIALIZED_VERSION = 0x01;

    /**
     * 对票据进行串行化
     * @param ticket 串行的票据数据
     * @return 串行后的结果
     * @throws IOException 异常
     */
    public static byte[] serialize(FormsAuthenticationTicket ticket) throws IOException {

        ByteArrayOutputStream ticketWriter = new ByteArrayOutputStream();
        ticketWriter.write(CURRENT_TICKET_SERIALIZED_VERSION);

        ticketWriter.write((byte)ticket.getVersion());
        // long到byte是注意要使用小端存储
        ticketWriter.write(longToBytes(ticket.getIssueDateUtcTick()));

        ticketWriter.write((byte)0xfe);

        ticketWriter.write(longToBytes(ticket.getExpirationUtcTick()));

        ticketWriter.write(booleanToByte(ticket.isPersistent()));

        ticketWriter.write(stringToBytes(ticket.getName()));

        ticketWriter.write(stringToBytes(ticket.getUserData()));

        ticketWriter.write(stringToBytes(ticket.getCookiePath()));

        ticketWriter.write((byte)0xff);
        return ticketWriter.toByteArray();
    }

    public static FormsAuthenticationTicket deserialize(byte[] serializedTicket) throws IOException {
        FormsAuthenticationTicket ticket = new FormsAuthenticationTicket();
//        ByteArrayInputStream ticketReader = new ByteArrayInputStream(serializedTicket);

        ByteBuffer ticketBuffer = ByteBuffer.wrap(serializedTicket);

        if(ticketBuffer.get() != CURRENT_TICKET_SERIALIZED_VERSION){
            return null;
        }
        ticket.setVersion(ticketBuffer.get());
        byte[] timeLong = new byte[8];
        ticketBuffer.get(timeLong);
        ticket.setIssueDateUtcTick(bytesToLong(timeLong));
        // 空读一位0xfe
        ticketBuffer.get();
        ticketBuffer.get(timeLong);
        ticket.setExpirationUtcTick(bytesToLong(timeLong));
        if(ticketBuffer.get()==0){
            ticket.setPersistent(false);
        }else {
            ticket.setPersistent(true);
        }
        int strLength = ticketBuffer.get()*2;
        byte[] nameByte = new byte[strLength];
        ticketBuffer.get(nameByte);
        ticket.setName(bytesToString(nameByte));
        //(short) (data[i] & 0x0FF);
        strLength = (short)(ticketBuffer.get() & 0x0FF) *2;
        nameByte = new byte[strLength];
        ticketBuffer.get(nameByte);
        ticket.setUserData(bytesToString(nameByte));
        strLength = ticketBuffer.get()*2;
        nameByte = new byte[strLength];
        ticketBuffer.get(nameByte);
        ticket.setCookiePath(bytesToString(nameByte));
        if(-1 != ticketBuffer.get()  || ticketBuffer.position()!= serializedTicket.length) {
            return null;
        }

        return ticket;
    }

    /**
     * 字节转long类，注意为小端
     * @param array 待转字节
     * @return 转回的Long
     */
    static long bytesToLong(byte[] array){
        return ((((long) array[ 0] & 0xff) << 0)
                | (((long) array[ 1] & 0xff) << 8)
                | (((long) array[ 2] & 0xff) << 16)
                | (((long) array[ 3] & 0xff) << 24)
                | (((long) array[ 4] & 0xff) << 32)
                | (((long) array[ 5] & 0xff) << 40)
                | (((long) array[ 6] & 0xff) << 48)
                | (((long) array[ 7] & 0xff) << 56));
    }

    /**
     * long转字节，注意为小端
     * @param n 待转数
     * @return 转回的字节
     */
    static byte[] longToBytes(long n) {

        byte[] b = new byte[8];
        b[0] = (byte) (n & 0xff);
        b[1] = (byte) (n >> 8  & 0xff);
        b[2] = (byte) (n >> 16 & 0xff);
        b[3] = (byte) (n >> 24 & 0xff);
        b[4] = (byte) (n >> 32 & 0xff);
        b[5] = (byte) (n >> 40 & 0xff);
        b[6] = (byte) (n >> 48 & 0xff);
        b[7] = (byte) (n >> 56 & 0xff);
        return b;
    }

    private static byte booleanToByte(Boolean x){
        return (byte)(x?0x01:0x00);
    }

    /**
     * 字符转字节，
     * @param x
     * @return
     */
    private static byte[] stringToBytes(String x){
        byte[] bytes = new byte[x.length() * 2+1];
        bytes[0] = (byte)x.length();
        for(int i=0;i<x.length();i++){
            char c = x.charAt(i);
            bytes[1 + 2 * i] = (byte) c;
            bytes[1 + 2 * i + 1] = (byte) (c>> 8);

        }

        return bytes;
    }

    /**
     * 字节转字符
     * @param x
     * @return
     */
    private static String bytesToString(byte[] x){
        char[] hex = new char[x.length / 2];
        for(int i=0;i<hex.length;i++){
            hex[i] = (char)(x[i*2] + (x[i*2+1]<<8));
        }
        return new String(hex);
    }

}
