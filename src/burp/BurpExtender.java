import burp.*;
import java.time.Instant;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.util.TimeZone;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.io.PrintWriter;
import java.util.List;
import java.time.ZonedDateTime;
import java.time.ZoneId;
import java.time.Duration;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import javax.swing.text.AbstractDocument;
import javax.swing.text.DocumentFilter;
import javax.swing.text.PlainDocument;
import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;


public class BurpExtender implements IBurpExtender, IHttpListener, ITab
{
    private burp.IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;
    private IBurpExtenderCallbacks callbacks;
    
    private JPanel panel;
    private JLabel currentTimeStampLabel;
    private JLabel currentUnixTimeLabel;
    private JLabel currentUnixTimeWithOffsetLabel;
    private Timer timer;
    
    private String selectedTimezone = "UTC";
    private String selectedDateFormat = "yyyy-MM-dd HH:mm:ss z";
    private String selectedOffset = "+";
    private String selectedTimeUnit = "sec";
    private int selectedOffsetValue = 0;

    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
    	this.callbacks = callbacks;
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(),true);

        // set our extension name
        callbacks.setExtensionName("Timestamp Injector");

        // register ourselves as an HTTP listener
        callbacks.registerHttpListener(this);
        
        // Create the tab
        SwingUtilities.invokeLater(() -> {
            createBurpTab();
            startTimer();
            callbacks.addSuiteTab(this);
        });
    }
    
    private void createBurpTab() {
    
    	int row = 0;

        panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5); // Padding around components
        
        
        gbc.gridx = 0;
        JLabel currentTimeLabel = new JLabel("Current Time:");
        panel.add(currentTimeLabel, gbc);
        
 
        
        currentUnixTimeLabel = new JLabel("");
        gbc.gridx = 1;
        gbc.gridy = row;
        panel.add(currentUnixTimeLabel, gbc);
        

        
        row++;
        
        
        gbc.gridx = 0;
        gbc.gridy = row;
        JLabel timeLabel = new JLabel("Time Offset:");
        panel.add(timeLabel, gbc);
        
        gbc.gridx = 1;
        gbc.gridy = row;
        JPanel subPanel2 = new JPanel();
        
        
        String[] offsets = {"+","-"};
        JComboBox<String> offsetSelector = new JComboBox<>(offsets);
        offsetSelector.setPreferredSize(new Dimension(40, 20));
        offsetSelector.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                selectedOffset = (String) offsetSelector.getSelectedItem();
            }
        });
        subPanel2.add(offsetSelector);
        
        JTextField offsetValueText = new JTextField("", 10);
        offsetValueText.setPreferredSize(new Dimension(30, 20));
        ((PlainDocument) offsetValueText.getDocument()).setDocumentFilter(new NumericFilter());

        offsetValueText.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                updateOffset(offsetValueText.getText());
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                updateOffset(offsetValueText.getText());
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                // Implemented but not used for plain text fields
            }
        });
   
        subPanel2.add(offsetValueText);
        
        String[] units = {"msec","sec","min","hr","day"};
        JComboBox<String> unitSelector = new JComboBox<>(units);
        unitSelector.setPreferredSize(new Dimension(70, 20));
        unitSelector.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                selectedTimeUnit = (String) unitSelector.getSelectedItem();
            }
        });
        unitSelector.setSelectedItem(selectedTimeUnit);
        subPanel2.add(unitSelector);
        
        panel.add(subPanel2, gbc);
        
        row++;
        
        gbc.gridx = 0;
        gbc.gridy = row;
        JLabel timeWithOffsetLabel = new JLabel("Time w/ Offset:");
        panel.add(timeWithOffsetLabel, gbc);
        
        
        currentUnixTimeWithOffsetLabel = new JLabel("");
        gbc.gridx = 1;
        gbc.gridy = row;
        panel.add(currentUnixTimeWithOffsetLabel,gbc);
     
        row++;
                
        gbc.gridx = 0;
        gbc.gridy = row;
        JLabel timezoneLabel = new JLabel("Timezone:");
        panel.add(timezoneLabel, gbc);


        // Create the timezone selector
        String[] timezones = TimeZone.getAvailableIDs();
        JComboBox<String> timezoneSelector = new JComboBox<>(timezones);
        timezoneSelector.setSelectedItem(selectedTimezone);
        gbc.gridx = 1;
        gbc.gridy = row;
        panel.add(timezoneSelector, gbc);

        // Add an action listener to handle selection
        timezoneSelector.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                selectedTimezone = (String) timezoneSelector.getSelectedItem();
            }
        });
        panel.add(Box.createVerticalStrut(10));
        
        row++;
        
        // Create Date Format Input
        JLabel timestampLabel = new JLabel("Timestamp Format:");
        gbc.gridx = 0;
        gbc.gridy = row;
        panel.add(timestampLabel, gbc);
        
        JTextField textField = new JTextField(selectedDateFormat, 20);
        textField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                updateDateFormat(textField.getText());
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                updateDateFormat(textField.getText());
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                updateDateFormat(textField.getText());
            }
        });
        gbc.gridx = 1;
        gbc.gridy = row;
        panel.add(textField, gbc);
        
        row++;
        
        gbc.gridx = 0;
        gbc.gridy = row;        
        JLabel timneStampLabel = new JLabel("Timestamp w/ Offset:");
        panel.add(timneStampLabel, gbc);
        
        currentTimeStampLabel = new JLabel("");

        
        gbc.gridx = 1;
        gbc.gridy = row;
        panel.add(currentTimeStampLabel, gbc);
        
        row+=2;
        
        /*
        
        JLabel commandsLabel = new JLabel("Commands:");
        gbc.gridx = 0;
        gbc.gridy = row;
        panel.add(commandsLabel, gbc);
        
        String[] commands = {"UnixTimeS","UnixTimeMS","TimeStamp","URLTimeStamp"};
        String[] explanations = {}
        gbc.gridx = 1;
        
        for (int i=0; i<commands.length; i++) {
        	String command = commands[i];
        	JButton copyButton = new JButton(command);
        	copyButton.setToolTipText("Copy Command to Clipboard");
		panel.add(copyButton, gbc);
		row++;
		gbc.gridy = row;

		// Add action listener to the button
		copyButton.addActionListener(new ActionListener() {
		    @Override
		    public void actionPerformed(ActionEvent e) {
		        // Copy text to clipboard
		        StringSelection stringSelection = new StringSelection(command);
		        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(stringSelection, null);		
		    }
		});
        
        }
        */
       
    }
    
    private void startTimer() {
        timer = new Timer(1000, new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                Instant offsetTime = getCurrentInstantWithOffset();
                long unixTimeWithOffset = offsetTime.getEpochSecond();
                Instant now = Instant.now();
                long unixTimeNow = now.getEpochSecond();
                
                currentUnixTimeWithOffsetLabel.setText(Long.toString(unixTimeWithOffset));
                currentUnixTimeLabel.setText(Long.toString(unixTimeNow));
                
                Date dateWithOffset = Date.from(offsetTime);
                String timeStamp = formatDate(dateWithOffset);
                
                if (timeStamp != null) {
                	currentTimeStampLabel.setText(timeStamp);
                }
                
                
            }
        });
        timer.start();
    }
    
    private String formatDate(Date date) {
        try {
            SimpleDateFormat sdf = new SimpleDateFormat(selectedDateFormat);
            sdf.setTimeZone(TimeZone.getTimeZone(selectedTimezone));
            String dateString = sdf.format(date); 
            return dateString;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
    
    private Instant getCurrentInstantWithOffset()
    {
    	Instant now = Instant.now();
    	
    	int negMultiplier = selectedOffset == "+" ? 1 : -1;
    	long multiplier;
    	
    	switch (selectedTimeUnit) {
    		case "sec":
    			multiplier = 1000;
    			break;
    		case "min":
    			multiplier = 60000;
    			break;
    		case "hr": 
    			multiplier = 3600000;
    			break;
    		case "day":
    			multiplier = 86400000;
    			break;
    		default:
    			multiplier = 1;

    	}
    	
    	Duration offset = Duration.ofMillis(this.selectedOffsetValue * negMultiplier * multiplier);
	return now.plus(offset);
    }

    private void updateDateFormat(String dateFormat)
    {
    	this.selectedDateFormat = dateFormat;
    	String formatedDate = formatDate(new Date());
    	currentTimeStampLabel.setText(formatedDate == null ? "Invalid Date Format" : "");
    }
    
    private void updateOffset(String text)
    {
        try {
            this.selectedOffsetValue = Integer.parseInt(text);
        } catch (NumberFormatException e) {
            this.selectedOffsetValue = 0;
        }
    }
    
    private RequestModResult modifyRequestContent(String content, Instant now, Date dateNow)
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
                String formatedDate = formatDate(dateNow);
                try {
                	ret = ret.replaceAll("URLTimeStamp", URLEncoder.encode(formatedDate, "UTF-8"));
                } catch (UnsupportedEncodingException e) {
            		stdout.println("Invalid URL-encoding conversion: " + formatedDate);
        	}
        	ret = ret.replaceAll("TimeStamp", formatedDate);

                updated = true;
            }
    
            return new RequestModResult(ret, updated);
    }
    

    //
    // implement IHttpListener
    //
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, burp.IHttpRequestResponse messageInfo)
    {
        boolean updated = false;
        Instant now = getCurrentInstantWithOffset();
        Date dateNow = Date.from(now);

        // only process requests
        if (messageIsRequest) {
            // get the HTTP service for the request
            burp.IHttpService httpService = messageInfo.getHttpService();
            burp.IRequestInfo iRequest = helpers.analyzeRequest(messageInfo);

            String request = new String(messageInfo.getRequest());

            List<String> headers = iRequest.getHeaders();
            // get the request body
            String reqBody = request.substring(iRequest.getBodyOffset());
            
            RequestModResult reqBodyMod = modifyRequestContent(reqBody, now, dateNow);            
            reqBody = reqBodyMod.content;
            updated = reqBodyMod.updated;

	    
            for (int i = 0; i < headers.size(); i++) {
                String header = headers.get(i);                
                RequestModResult headerBodyMod = modifyRequestContent(header, now, dateNow);            
                updated = headerBodyMod.updated;
                headers.set(i, headerBodyMod.content);
            }
            

            if (updated) {
                stdout.println("-----Request Before Plugin Update-------");
                stdout.println(helpers.bytesToString(messageInfo.getRequest()));
                stdout.println("-----end output-------");

                byte[] message = helpers.buildHttpMessage(headers, reqBody.getBytes());
                messageInfo.setRequest(message);

                stdout.println("-----Request After Plugin Update-------");
                stdout.println(helpers.bytesToString(messageInfo.getRequest()));
                stdout.println("-----end output-------");
            }
        }
    }
    
    @Override
    public String getTabCaption() {
        return "Timestamp Injector";
    }

    @Override
    public Component getUiComponent() {
        return panel;
    }
}

class NumericFilter extends DocumentFilter {
        @Override
        public void insertString(FilterBypass fb, int offset, String string, AttributeSet attr) throws BadLocationException {
            if (isNumeric(string)) {
                super.insertString(fb, offset, string, attr);
            }
        }

        @Override
        public void replace(FilterBypass fb, int offset, int length, String string, AttributeSet attrs) throws BadLocationException {
            if (isNumeric(string)) {
                super.replace(fb, offset, length, string, attrs);
            }
        }

        @Override
        public void remove(FilterBypass fb, int offset, int length) throws BadLocationException {
            super.remove(fb, offset, length); // Allow removal of characters
        }

        // Helper method to check if a string is numeric
        private boolean isNumeric(String str) {
            return str != null && str.matches("\\d*"); // Matches digits only
        }
    }
    
class RequestModResult {
	public String content;
	public boolean updated;
	
	public RequestModResult(String content, boolean updated) {
		this.content = content;
		this.updated = updated;
	}
}

