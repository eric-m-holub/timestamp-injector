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
import java.util.ArrayList;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

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

                ArrayList<String> injPoints = checkContentForInjectionPoints(header.value());

                if (injPoints.size() > 0) {
               		String headerMod = modifyRequestContent(header.value(), injPoints, now, dateNow);
               		printBeforeAfter("Header", header.toString(), header.name()+": "+headerMod);
               		finalRequest = finalRequest.withHeader(HttpHeader.httpHeader(header.name(),headerMod));
                }
        }


        ArrayList<String> injPointsBody = checkContentForInjectionPoints(body);
        if (injPointsBody.size() > 0) {
       		String reqBodyMod = modifyRequestContent(body, injPointsBody, now, dateNow);
       		printBeforeAfter("Body", body, reqBodyMod);
        	finalRequest = finalRequest.withBody(reqBodyMod);
        }

        return continueWith(finalRequest, annotations);
    }


    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        Annotations annotations = responseReceived.annotations();
        return continueWith(responseReceived, annotations);
    }

    private ArrayList<String> checkContentForInjectionPoints(String content)
    {
    	String[] injectionPoints = {"UnixTimeS","UnixTimeMS","URLTimeStamp","TimeStamp"};
    	ArrayList<String> ret = new ArrayList();

    	for (int i=0; i<injectionPoints.length; i++) {
    		String injPoint = injectionPoints[i];
    		if (content.contains(injPoint)) {
    			ret.add(injPoint);
    		}
    	}

    	return ret;
    }


    // Search the HTTP request body and headers for strings to replace and replace them
    public String modifyRequestContent(String content, ArrayList<String> injPoints, Instant now, Date dateNow)
    {
    	    String ret = content;
    	    String formatedDate = main.formatDate(dateNow);

            if (injPoints.contains("UnixTimeS")) {
                long unixTimeSeconds = now.getEpochSecond();
                String unixTimeSecondsString = Long.toString(unixTimeSeconds);
                ret = ret.replaceAll("UnixTimeS", unixTimeSecondsString);
            }

            if (injPoints.contains("UnixTimeMS")) {
                long unixTimeMilliseconds = now.toEpochMilli();
                String unixTimeMilliSsecondsString = Long.toString(unixTimeMilliseconds);
                ret = ret.replaceAll("UnixTimeMS", unixTimeMilliSsecondsString);
            }

            if (injPoints.contains("URLTimeStamp") && formatedDate != null) {
	    	        try {
			               ret = ret.replaceAll("URLTimeStamp", URLEncoder.encode(formatedDate, "UTF-8"));
		             } catch (UnsupportedEncodingException e) {
		  	             main.log.logToError("Error URL-encoding value: " + ret);
		             }
            }

            if (injPoints.contains("TimeStamp") && formatedDate != null) {
		            ret = ret.replaceAll("TimeStamp", formatedDate);
            }

            return ret;
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
