package org.example;


import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;

/**
 * 对参数进行签名
 * <p>
 * Created by wangyan on 2022/6/11.
 */
public class SignUtils {

    /**
     * 对paramValues进行签名，其中ignoreParamNames这些参数不参与签名
     *
     * @param paramValues
     * @param ignoreParamNames
     * @param secret
     * @return
     */
    public static String sign(Map<String, String> paramValues, List<String> ignoreParamNames, String secret) {
        try {
            StringBuilder sb = new StringBuilder();
            List<String> paramNames = new ArrayList<String>(paramValues.size());
            paramNames.addAll(paramValues.keySet());
            if (ignoreParamNames != null && ignoreParamNames.size() > 0) {
                for (String ignoreParamName : ignoreParamNames) {
                    paramNames.remove(ignoreParamName);
                }
            }
            Collections.sort(paramNames);

            sb.append(secret);
            for (String paramName : paramNames) {
                sb.append(paramName).append(paramValues.get(paramName) == null ? "" : paramValues.get(paramName));
            }
            sb.append(secret);
            System.out.println("签名原串：" + sb.toString());
            byte[] sha1Digest = getSHA1Digest(sb.toString());
            return byte2hex(sha1Digest);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] getSHA1Digest(String data) throws IOException {
        byte[] bytes;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            bytes = md.digest(data.getBytes("UTF-8"));
        } catch (GeneralSecurityException gse) {
            throw new IOException(gse);
        }
        return bytes;
    }

    /**
     * 二进制转十六进制字符串
     *
     * @param bytes
     * @return
     */
    private static String byte2hex(byte[] bytes) {
        StringBuilder sign = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            String hex = Integer.toHexString(bytes[i] & 0xFF);
            if (hex.length() == 1) {
                sign.append("0");
            }
            sign.append(hex.toUpperCase());
        }
        return sign.toString();
    }


    //------------------------------------ 工具 ------------------------------------

    /**
     * Get 请求 支持token
     *
     * @param url    地址
     * @param params 参数
     * @param token  请求头token
     * @return
     * @throws Exception
     */
    public static String Get(String url, Map<String, String> params, String token) throws Exception {
        ArrayList<NameValuePair> pairs = covertParams2NVPS(params);
        StringBuffer buf = new StringBuffer();
        buf.append(url);
        buf.append("?");
        for (int i = 0; i < pairs.size(); i++) {
            NameValuePair nameValuePair = pairs.get(i);
            if (i == 0) {
                buf.append(nameValuePair.getName() + "=" + nameValuePair.getValue());
            } else {
                buf.append("&" + nameValuePair.getName() + "=" + nameValuePair.getValue());
            }
        }
        HttpClient client = HttpClients.createDefault();
        url=buf.toString();
        url = url.replaceAll("\\s*", "");

        HttpGet get = new HttpGet(url);
        try {
            if (token != null) {
                get.addHeader("token", token);
            }
            // 传输的类型
            get.addHeader("Content-Type", "application/x-www-form-urlencoded");
            // 执行请求
            HttpResponse response = client.execute(get);
            HttpEntity entity = response.getEntity();
            String result = EntityUtils.toString(entity, "UTF-8");
            return result;
        } catch (ClientProtocolException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static ArrayList<NameValuePair> covertParams2NVPS(Map<String, String> params) {
        ArrayList<NameValuePair> pairs = new ArrayList<>();
        if (params == null || params.size() == 0) {
            return pairs;
        }
        for (Map.Entry<String, String> param : params.entrySet()) {
            Object value = param.getValue();
            if (value instanceof String[]) {
                String[] values = (String[]) value;
                for (String v : values) {
                    pairs.add(new BasicNameValuePair(param.getKey(), v));
                }
            } else {
                if (value instanceof Integer) {
                    value = Integer.toString((Integer) value);
                } else if (value instanceof Long) {
                    value = Long.toString((Long) value);
                }
                pairs.add(new BasicNameValuePair(param.getKey(), (String) value));
            }
        }
        return pairs;
    }

    //----------------------------------- 请求 -----------------------------------

    private static final String appId = "kplm_0000001";
    private static final String secret = "16542bd0a6a0404798b8b7827be89da8";
    private static final String apiurl = "https://jifugou.picp.vip/system/gscaee/entrustedGoodApi";

    public static void main(String[] args) throws Exception {
        long nowTimestamp = Instant.now().getEpochSecond();

        //参数签名测试例子
        Map<String, String> data = new HashMap<>();

        data.put("userId", "13389186557");
        data.put("otcCode", "100000");
        data.put("pickupAmount", "300");

        data.put("appid", appId);
        data.put("timestamp", String.valueOf(nowTimestamp));
        String sign = sign(data, null, secret);
        data.put("sign", sign);

        System.out.println("得到签名sign: " + sign);
        String resp = Get(apiurl, data, null);
        System.out.println(resp);
    }

}
