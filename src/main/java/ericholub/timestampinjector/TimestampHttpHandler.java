package ericholub.timestampinjector;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.logging.Logging;
import java.util.Date;
import java.time.Instant;
import java.util.List;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

import ericholub.timestampinjector.RequestModResult;

import static burp.api.montoya.http.handler.RequestToBeSentAction.continueWith;
import static burp.api.montoya.http.handler.ResponseReceivedAction.continueWith;
import static burp.api.montoya.http.message.params.HttpParameter.urlParameter;

class TimestampHttpHandler implements HttpHandler {

    public TimestampInjector main;

    public TimestampHttpHandler(TimestampInjector main) {
        this.main = main;
    }


    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        Annotations annotations = requestToBeSent.annotations();
        Instant now = main.getCurrentInstantWithOffset();
        Date dateNow = Date.from(now);
        
        List<HttpHeader> headers = requestToBeSent.headers();
        String body = requestToBeSent.bodyToString();   
        
        HttpRequest finalRequest = (HttpRequest) requestToBeSent;   
        
        for (int i = 0; i < headers.size(); i++) {
                HttpHeader header = headers.get(i);
                RequestModResult headerMod = modifyRequestContent(header.value(), now, dateNow);
                if (headerMod.updated) {
                	printBeforeAfter("Header", header.toString(), header.name()+": "+headerMod.content);
               		finalRequest = finalRequest.withHeader(HttpHeader.httpHeader(header.name(),headerMod.content));
                }
        }

             
        RequestModResult reqBodyMod = modifyRequestContent(body, now, dateNow);
        
        if (reqBodyMod.updated) {  	
        	printBeforeAfter("Body", body, reqBodyMod.content);
        	finalRequest = finalRequest.withBody(reqBodyMod.content);
        }
          
        return continueWith(finalRequest, annotations);
    }

    
    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        Annotations annotations = responseReceived.annotations();
        return continueWith(responseReceived, annotations);
    }
    
    
    // Search the HTTP request body and headers for strings to replace and replace them
    public RequestModResult modifyRequestContent(String content, Instant now, Date dateNow)
    {
    	    String ret = content;
    	    boolean updated = false;

            if (ret.contains("UnixTimeS")) {
                long unixTimeSeconds = now.getEpochSecond();
                String unixTimeSecondsString = Long.toString(unixTimeSeconds);
                ret = ret.replaceAll("UnixTimeS", unixTimeSecondsString);
                updated = true;
            }

            if (ret.contains("UnixTimeMS")) {
                long unixTimeMilliseconds = now.toEpochMilli();
                String unixTimeMilliSsecondsString = Long.toString(unixTimeMilliseconds);
                ret = ret.replaceAll("UnixTimeMS", unixTimeMilliSsecondsString);
                updated = true;
            }

            if (ret.contains("URLTimeStamp") || ret.contains("TimeStamp")) {
                String formatedDate = main.formatDate(dateNow);

                if (formatedDate != null) {
		        try {
		        	ret = ret.replaceAll("URLTimeStamp", URLEncoder.encode(formatedDate, "UTF-8"));
		        } catch (UnsupportedEncodingException e) {
		          	main.log.logToError("Error URL-encoding value: " + ret);
			}

			ret = ret.replaceAll("TimeStamp", formatedDate);
		        updated = true;
                }
            }

            return new RequestModResult(ret, updated);
    }
    
    private void printBeforeAfter(String callContent, String before, String after)
    {
    	this.main.log.logToOutput("Modified: " + callContent);
    	this.main.log.logToOutput("Before: ");
    	this.main.log.logToOutput(before);
    	this.main.log.logToOutput("After: ");
    	this.main.log.logToOutput(after);   	
    	this.main.log.logToOutput("---------------------------------------\n");
    
    }
}
