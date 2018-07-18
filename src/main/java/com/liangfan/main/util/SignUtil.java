package com.liangfan.main.util;

import lombok.extern.slf4j.Slf4j;
import sun.misc.BASE64Encoder;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class SignUtil {


    public static String generateSignature(String data, String key) {
        byte[] byteHMAC = null;
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            SecretKeySpec spec = new SecretKeySpec(key.getBytes(), "HmacSHA1");
            mac.init(spec);
            byteHMAC = mac.doFinal(data.getBytes());
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException ignore) {
        }
        String oauth = new BASE64Encoder().encode(byteHMAC);
        return oauth;
    }
//
//    public static String getBaseString(Long current) throws UnsupportedEncodingException {
//        String bss;
//        bss = "GET" + "&"
//                + URLEncoder.encode(request_token_url, "utf-8") + "&";
//        String bass
//                ="oauth_consumer_key=" + consumer_key + "&oauth_nonce="
//                + current + "&oauth_signature_method="
//                + "HMAC-SHA1" + "&oauth_timestamp="
//                + current ;
//        bass = URLEncoder.encode(bass, "utf-8");
//        System.out.println(bss+bass);
//        return bss + bass;
//    }
//    public static void main(String[] args) throws UnsupportedEncodingException {
//        long currentTimeMillis = System.currentTimeMillis();
//        String s = generateSignature(getBaseString(currentTimeMillis), consumer_secret);
//        CloseableHttpClient httpClient = HttpClients.createDefault();
//        String url=
//                request_token_url+"?"+"oauth_consumer_key="+consumer_key+
//                "&oauth_signature_method="+"HMAC-SHA1"+"&oauth_signature="+s+"&oauth_timestamp="+currentTimeMillis+
//                        "&oauth_nonce="+currentTimeMillis;
//        HttpGet httpGet=new HttpGet(url);
//
//        try {
//            CloseableHttpResponse execute = httpClient.execute(httpGet);
//            StatusLine statusLine = execute.getStatusLine();
//
//                InputStream content = execute.getEntity().getContent();
//                byte[] bytes=new byte[1024];
//                StringBuilder buff=new StringBuilder();
//                while (content.read(bytes)!=-1){
//                    buff.append(new String(bytes));
//                }
//                System.out.println("token:"+buff.toString());
//
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//    }

}
