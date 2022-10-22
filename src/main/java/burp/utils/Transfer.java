package burp.utils;

import burp.BurpExtender;
import burp.FastInfoSetBurpException;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import com.sun.xml.fastinfoset.sax.SAXDocumentSerializer;
import org.jvnet.fastinfoset.FastInfosetSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXNotRecognizedException;
import org.xml.sax.SAXNotSupportedException;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.util.Iterator;
import java.util.List;

public class Transfer {

    /**
     * 对请求包进行Fastinfost编码
     * @param requestResponse 要处理的请求响应对象
     * @return 编码后的请求包
     */
    public static  byte[] encoding(IHttpRequestResponse requestResponse) throws SAXNotSupportedException, SAXNotRecognizedException, ParserConfigurationException {
        byte[] request = requestResponse.getRequest();
        List<String> headers = BurpExtender.helpers.analyzeRequest(request).getHeaders();
        //修改 application/fastinfoset
        Iterator<String> iter = headers.iterator();
        while (iter.hasNext()) {
            String reqHeader = iter.next().toLowerCase();
            //不对请求包重复编码
            if (reqHeader.contains("fastinfoset")) {
                return request;
            }
            if (reqHeader.contains("content-type")){
               iter.remove();
            }
        }
        headers.add("Content-Type: application/fastinfoset");

        IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(request);
        int bodyOffset = requestInfo.getBodyOffset();
        int body_length = request.length - bodyOffset;
        byte[] byteBody = new byte[body_length];
        System.arraycopy(request, bodyOffset, byteBody, 0, body_length);

        byte[] byte_encoding_body = encodeFastInfoSetStream(byteBody);
        return BurpExtender.helpers.buildHttpMessage(headers,byte_encoding_body);
    }

    /**
     * 编码成fastinfoset 格式
     * @param content
     * @return
     * @throws SAXNotSupportedException
     * @throws SAXNotRecognizedException
     * @throws ParserConfigurationException
     */
    private static byte[] encodeFastInfoSetStream(byte[] content) throws SAXNotSupportedException, SAXNotRecognizedException, ParserConfigurationException {
        InputStream xmlDocument = new ByteArrayInputStream(content);
        byte[] outarr = null;
        ByteArrayOutputStream fiDocument =  new ByteArrayOutputStream();
        SAXDocumentSerializer saxDocumentSerializer = new SAXDocumentSerializer();
        saxDocumentSerializer.setOutputStream(fiDocument);
        SAXParserFactory saxParserFactory = SAXParserFactory.newInstance();//防止xxe
        saxParserFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        saxParserFactory.setNamespaceAware(true);
        SAXParser saxParser=null;
        try {
            saxParser = saxParserFactory.newSAXParser();
        } catch (ParserConfigurationException e) {
            throw new burp.FastInfoSetBurpException(e);
        } catch (SAXException ex) {
            throw new burp.FastInfoSetBurpException(ex);
        }
        try {
            // Set the lexical handler
            saxParser.setProperty("http://xml.org/sax/properties/lexical-handler", saxDocumentSerializer);
        } catch (SAXNotRecognizedException ex) {
            throw new burp.FastInfoSetBurpException(ex);
        } catch (SAXNotSupportedException ex) {
            throw new burp.FastInfoSetBurpException(ex);
        }

        try {
            // Parse the XML document and convert to a fast infoset document
            saxParser.parse(xmlDocument, saxDocumentSerializer);

        } catch (SAXException ex) {
            throw new burp.FastInfoSetBurpException(ex);
        } catch (IOException ex) {
            throw new burp.FastInfoSetBurpException(ex);
        }
        try {
            fiDocument.close();
        } catch (IOException ex) {
            throw new burp.FastInfoSetBurpException(ex);
        }
        return fiDocument.toByteArray();
    }

    /**
     * 对编码过的请求包进行解码
     * @param requestResponse 已编码过的请求响应对象
     * @return 解码后的请求包
     * @throws UnsupportedEncodingException
     */
    public static byte[] decoding(IHttpRequestResponse requestResponse)  {
        byte[] request = requestResponse.getRequest();
        // 修改
        List<String> headers = BurpExtender.helpers.analyzeRequest(request).getHeaders();
        Iterator<String> iter = headers.iterator();
        Boolean isChunked = false;//是否被分块编码过
        while (iter.hasNext()) {
            String reqHeader = iter.next().toLowerCase();
            if (reqHeader.contains("content-type") && reqHeader.contains("fastinfoset")) {
                iter.remove();
                isChunked = true;
            }
            //if (reqHeader.contains("content-type")){
            //    iter.remove();
            //}
        }
        //不对未编码过的请求包解码
        if(!isChunked){
            return request;
        }
        headers.add("Content-Type: text/xml;charset=UTF-8");

        IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(request);
        int bodyOffset = requestInfo.getBodyOffset();
        int body_length = request.length - bodyOffset;
        byte[] byteBody = new byte[body_length];
        System.arraycopy(request, bodyOffset, byteBody, 0, body_length);

        byte[] mergeReqBody = decodeFastInfoSetStream(byteBody);

        return BurpExtender.helpers.buildHttpMessage(headers,mergeReqBody);
    }

    /**
     * 解码
     * @param content
     * @return
     */
    private static byte[] decodeFastInfoSetStream(byte[] content) {
        try (InputStream input = new ByteArrayInputStream(content); ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            TransformerFactory.newInstance().newTransformer().transform(new FastInfosetSource(input), new StreamResult(output));
            return output.toByteArray();
        } catch (Exception e) {
            throw new FastInfoSetBurpException(e);
        }
    }

    /**
     * 通过数据包头部是否存在application/fastinfoset头，来判断其是否被编码
     * @param requestResponse
     * @return 是否被编码
     */
    public static boolean isFastInFoSet(IHttpRequestResponse requestResponse){
        byte[] request = requestResponse.getRequest();
        List<String> headers = BurpExtender.helpers.analyzeRequest(request).getHeaders();
        Iterator<String> iter = headers.iterator();
        while (iter.hasNext()) {
            String reqHeader = iter.next().toLowerCase();
            if (reqHeader.contains("content-type") && reqHeader.contains("fastinfoset")) {
                return true;
            }
        }
        return false;
    }
}
