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


public class BurpExtender implements IBurpExtender, IHttpListener, ITab, IExtensionStateListener
{
    // Burp Extension variables
    private burp.IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;
    private IBurpExtenderCallbacks callbacks;

    // JPanel Interactive Elements
    private JPanel panel;
    private JLabel currentTimeStampLabel;
    private JLabel currentUnixTimeLabel;
    private JLabel currentUnixTimeWithOffsetLabel;
    private Timer timer;

    // User-defined values
    private String selectedTimezone = "UTC";
    private String selectedDateFormat = "yyyy-MM-dd HH:mm:ss z";
    private String selectedOffset = "+";
    private String selectedTimeUnit = "sec";
    private int selectedOffsetValue = 0;


    // Run when extension is loaded
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

        // Start listening for HTTP Requests
        callbacks.registerHttpListener(this);

        // Create the Extension Tab, and start Unix Clock Timer
        SwingUtilities.invokeLater(() -> {
            createBurpTab();
            startTimer();
            callbacks.addSuiteTab(this);
        });

        callbacks.registerExtensionStateListener(this);

        // Print out welcome message to output
        stdout.println("Timestamp Injector successfully loaded. Here are the injection commands:\n\nUnixTimeS — inject unix time (seconds)\nUnixTimeMS — inject unix time (milliseconds)\nTimeStamp — inject custom timestamp\nURLTimeStamp — inject custom timestamp (URL-encoded)\n");
    }

    private void createBurpTab() {

    	int row = 0;

	// Set grid layout
        panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5); // Padding around components

	// Create static label
        gbc.gridx = 0;
        JLabel currentTimeLabel = new JLabel("Current Time:");
        panel.add(currentTimeLabel, gbc);

	//Create label that displays current Unix time
        currentUnixTimeLabel = new JLabel("");
        gbc.gridx = 1;
        gbc.gridy = row;
        panel.add(currentUnixTimeLabel, gbc);

	//Next row!
        row++;

	// Create static label
        gbc.gridx = 0;
        gbc.gridy = row;
        JLabel timeLabel = new JLabel("Time Offset:");
        panel.add(timeLabel, gbc);

	// Shove next few elements into subpanel
        gbc.gridx = 1;
        gbc.gridy = row;
        JPanel subPanel2 = new JPanel();

	// Create selector for + or - offset
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

	// Create text field that only accepts numerical input for offset
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

	// Create selector for time unit
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

	// Next row!
        row++;

	// Create static label
        gbc.gridx = 0;
        gbc.gridy = row;
        JLabel timeWithOffsetLabel = new JLabel("Time w/ Offset:");
        panel.add(timeWithOffsetLabel, gbc);

	// Create label that displays Unix time with defined offset
        currentUnixTimeWithOffsetLabel = new JLabel("");
        gbc.gridx = 1;
        gbc.gridy = row;
        panel.add(currentUnixTimeWithOffsetLabel,gbc);

	// Next row!
        row++;

	// Create static label
        gbc.gridx = 0;
        gbc.gridy = row;
        JLabel timezoneLabel = new JLabel("Timezone:");
        panel.add(timezoneLabel, gbc);

	// Create selector for timezone
        String[] timezones = TimeZone.getAvailableIDs();
        JComboBox<String> timezoneSelector = new JComboBox<>(timezones);
        timezoneSelector.setSelectedItem(selectedTimezone);
        gbc.gridx = 1;
        gbc.gridy = row;
        panel.add(timezoneSelector, gbc);

        timezoneSelector.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                selectedTimezone = (String) timezoneSelector.getSelectedItem();
            }
        });
        panel.add(Box.createVerticalStrut(10));

	// Next row!
        row++;

	// Create static label
        JLabel timestampLabel = new JLabel("Timestamp Format:");
        gbc.gridx = 0;
        gbc.gridy = row;
        panel.add(timestampLabel, gbc);

	// Create text field for timestamp format
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

	// Next row!
        row++;

	// Create static label
        gbc.gridx = 0;
        gbc.gridy = row;
        JLabel timneStampLabel = new JLabel("Timestamp w/ Offset:");
        panel.add(timneStampLabel, gbc);

	// Create label that displays current timestamp
        currentTimeStampLabel = new JLabel("");
        gbc.gridx = 1;
        gbc.gridy = row;
        panel.add(currentTimeStampLabel, gbc);
    }

    // Timer which updates Unix time and timestamps values for a live view
    private void startTimer() {
        this.timer = new Timer(1000, new ActionListener() {
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

                Color color = timeStamp == null ? Color.RED : Color.BLACK;

                updateTimestampLabel(timeStamp == null ? "Invalid Timestamp Format" : timeStamp, color);

                if (timeStamp != null) {
                	currentTimeStampLabel.setText(timeStamp);
                }


            }
        });
        timer.start();
    }

    // Use defined timestamp format to create timestamp
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

    // Calculate Unix time with defined offset
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

    // Update timstamp label with text and color (indicates error)
    private void updateTimestampLabel(String text, Color color)
    {
    	currentTimeStampLabel.setForeground(color);
    	currentTimeStampLabel.setText(text);
    }

    // Run when user updates the timestamp format text field. Check if they enter an invalid value
    private void updateDateFormat(String dateFormat)
    {
    	this.selectedDateFormat = dateFormat;
    	String formatedDate = formatDate(new Date());

    	Color color = formatedDate == null ? Color.RED : Color.BLACK;
    	String text = formatedDate == null ? "Invalid Timestamp Format" : formatedDate;
    	updateTimestampLabel(text, color);
    }

    // Run when user updates the offset text field. Numeric filter already in place, convert string to int
    private void updateOffset(String text)
    {
        try {
            this.selectedOffsetValue = Integer.parseInt(text);
        } catch (NumberFormatException e) {
            stderr.println("Error parsing offset: " + text);
            this.selectedOffsetValue = 0;
        }
    }

    // Search the HTTP request body and headers for strings to replace and replace them
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

                if (formatedDate != null) {
		        try {
		        	ret = ret.replaceAll("URLTimeStamp", URLEncoder.encode(formatedDate, "UTF-8"));
		        } catch (UnsupportedEncodingException e) {
		          stderr.println("Error URL-encoding value: " + ret);
			}

			ret = ret.replaceAll("TimeStamp", formatedDate);
		        updated = true;
                }
            }

            return new RequestModResult(ret, updated);
    }

    // Burp native function which runs whenever Burp executes an HTTP request
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, burp.IHttpRequestResponse messageInfo)
    {
        boolean updated = false;
        Instant now = getCurrentInstantWithOffset();
        Date dateNow = Date.from(now);

        if (messageIsRequest) {

            burp.IHttpService httpService = messageInfo.getHttpService();
            burp.IRequestInfo iRequest = helpers.analyzeRequest(messageInfo);

            String request = new String(messageInfo.getRequest());
            List<String> headers = iRequest.getHeaders();
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

	    // Print to output whenever a HTTP request is changed
            if (updated) {
                stdout.println("-----Request Before Extension Update-------");
                stdout.println(helpers.bytesToString(messageInfo.getRequest()));
                stdout.println("-----end output-------");

                byte[] message = helpers.buildHttpMessage(headers, reqBody.getBytes());
                messageInfo.setRequest(message);

                stdout.println("-----Request After Extension Update-------");
                stdout.println(helpers.bytesToString(messageInfo.getRequest()));
                stdout.println("-----end output-------");
            }
        }
    }

    // Define tab name
    @Override
    public String getTabCaption() {
        return "Timestamp Injector";
    }

    // Return UI Tab
    @Override
    public Component getUiComponent() {
        return panel;
    }

    // Run Function when extension is unloaded from Burp Suite
    @Override
    public void extensionUnloaded() {
        this.timer.stop();
    }
}


// Class that filters text input to only include numeric characters
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
            super.remove(fb, offset, length);
        }


        private boolean isNumeric(String str) {
            return str != null && str.matches("\\d*");
        }
    }

// Return result from HTTP request check
class RequestModResult {
	public String content;
	public boolean updated;

	public RequestModResult(String content, boolean updated) {
		this.content = content;
		this.updated = updated;
	}
}
