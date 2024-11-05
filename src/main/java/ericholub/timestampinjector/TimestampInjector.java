package ericholub.timestampinjector;

import burp.api.montoya.*;
import burp.api.montoya.logging.Logging;
import javax.swing.*;
import java.awt.*;
import java.text.SimpleDateFormat;
import java.util.TimeZone;
import java.util.Date;
import java.time.Instant;
import java.util.List;
import java.time.ZonedDateTime;
import java.time.ZoneId;
import java.time.Duration;
import burp.api.montoya.persistence.PersistedObject;
import java.lang.reflect.Field;

import ericholub.timestampinjector.NumericFilter;
import ericholub.timestampinjector.TimestampInjectorTab;
import ericholub.timestampinjector.TimestampHttpHandler;


//Burp will auto-detect and load any class that extends BurpExtension.
public class TimestampInjector implements BurpExtension {

    // Montoya Variables
    public Logging log;
    private TimestampInjectorTab tab;
    public PersistedObject persist;

    // User-defined values w/ defaults
    public String selectedTimezone = "UTC";
    public String selectedDateFormat = "yyyy-MM-dd HH:mm:ss z";
    public String selectedOffset = "+";
    public String selectedTimeUnit = "secs";
    public int selectedOffsetValue = 0;

    @Override
    public void initialize(MontoyaApi api) {
    	String extensionTitle = "Timestamp Injector";   
    	
        api.extension().setName(extensionTitle);
        log = api.logging();	
	persist = api.persistence().extensionData();
	
	loadValuesFromPersistence();
        
	tab = new TimestampInjectorTab(this);
	tab.startTimer();	
	api.userInterface().registerSuiteTab(extensionTitle, tab);
	
	log.logToOutput("Timestamp Injector successfully loaded. Here are the injection commands:\n\nUnixTimeS — inject unix time (seconds)\nUnixTimeMS — inject unix time (milliseconds)\nTimeStamp — inject custom timestamp\nURLTimeStamp — inject custom timestamp (URL-encoded)\n");
	
	api.http().registerHttpHandler(new TimestampHttpHandler(this));
	
	api.extension().registerUnloadingHandler(() -> {
            log.logToOutput("Unloading Extension");
            tab.stopTimer();
        });
    }

    // Use defined timestamp format to create timestamp
    public String formatDate(Date date) {
        try {
            SimpleDateFormat sdf = new SimpleDateFormat(selectedDateFormat);
            sdf.setTimeZone(TimeZone.getTimeZone(selectedTimezone));
            String dateString = sdf.format(date);
            return dateString;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    // Calculate Unix time with defined offset
    public Instant getCurrentInstantWithOffset()
    {
    	Instant now = Instant.now();

    	int negMultiplier = selectedOffset == "+" ? 1 : -1;
    	long multiplier;

    	switch (selectedTimeUnit) {
    		case "secs":
    			multiplier = 1000;
    			break;
    		case "mins":
    			multiplier = 60000;
    			break;
    		case "hrs":
    			multiplier = 3600000;
    			break;
    		case "days":
    			multiplier = 86400000;
    			break;
    		default:
    			multiplier = 1;

    	}

    	Duration offset = Duration.ofMillis(this.selectedOffsetValue * negMultiplier * multiplier);
    	return now.plus(offset);
    }
    
    
    // Load user-defined values from persistence
    private void loadValuesFromPersistence() {
    	String[] keys = {"selectedTimezone","selectedDateFormat","selectedOffset","selectedTimeUnit","selectedOffsetValue"};
    	
    	for (int i=0; i<keys.length; i++) {
    		String key = keys[i];
    		
    		
    		if (key == "selectedOffsetValue") {
    			Integer value = persist.getInteger(key);
    			if (value != null) {
    				setValue(key,value);
    			}
    			
    		} else {
    			String value = persist.getString(key);
    			if (value != null) {
    				setValue(key,value);
    			}
    		}
    	
    	}
    
    }
    
    // Set user-defined values from persistence
    private void setValue(String key, Object value) {
    	//log.logToOutput("Loading -- " + key + ": " + value.toString() + "\n");
        try {
            Field field = this.getClass().getDeclaredField(key);
            field.set(this, value);
        } catch (Exception e) {
            log.logToError("Failed to load value: " + key);
        }
    
    }
    
}
