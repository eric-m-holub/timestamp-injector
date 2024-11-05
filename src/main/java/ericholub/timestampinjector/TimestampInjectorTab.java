package ericholub.timestampinjector;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.PlainDocument;
import burp.api.montoya.persistence.Persistence;

import java.util.Date;
import java.util.TimeZone;
import java.time.Instant;

import ericholub.timestampinjector.TimestampInjector;

public class TimestampInjectorTab extends JPanel {

	// JPanel Interactive Elements
	public JPanel panel;
	public JLabel currentTimeStampLabel;
	public JLabel currentUnixTimeLabel;
	public JLabel currentUnixTimeWithOffsetLabel;
	public Timer timer;

	private TimestampInjector main;

	public TimestampInjectorTab(TimestampInjector main) {

		this.main = main;

	   	int row = 0;

		// Set grid layout
		setLayout(new GridBagLayout());
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.insets = new Insets(5, 5, 10, 5); // Padding around components

		// Create static label
		gbc.gridx = 0;
		JLabel currentTimeLabel = new JLabel("Current Time:");
		this.add(currentTimeLabel, gbc);

		//Create label that displays current Unix time
		currentUnixTimeLabel = new JLabel("");
		gbc.gridx = 1;
		gbc.gridy = row;
		this.add(currentUnixTimeLabel, gbc);

		//Next row!
		row++;

		// Create static label
		gbc.gridx = 0;
		gbc.gridy = row;
		JLabel timeLabel = new JLabel("Time Offset:");
		this.add(timeLabel, gbc);

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
		    	String value = (String) offsetSelector.getSelectedItem();
		        main.selectedOffset = value;
		        main.persist.setString("selectedOffset", value);
		    }
		});
		offsetSelector.setSelectedItem(main.selectedOffset);
		subPanel2.add(offsetSelector);

		// Create text field that only accepts numerical input for offset
		String offsetText = main.selectedOffsetValue == 0 ? "" : String.valueOf(main.selectedOffsetValue);
		JTextField offsetValueText = new JTextField(offsetText, 10);
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
		String[] units = {"msecs","secs","mins","hrs","days"};
		JComboBox<String> unitSelector = new JComboBox<>(units);
		unitSelector.setPreferredSize(new Dimension(70, 20));
		unitSelector.addActionListener(new ActionListener() {
		    @Override
		    public void actionPerformed(ActionEvent e) {
		        String value = (String) unitSelector.getSelectedItem();
		        main.selectedTimeUnit = value;
		        main.persist.setString("selectedTimeUnit", value);
		    }
		});
		unitSelector.setSelectedItem(main.selectedTimeUnit);
		subPanel2.add(unitSelector);

		this.add(subPanel2, gbc);

		// Next row!
		row++;

		// Create static label
		gbc.gridx = 0;
		gbc.gridy = row;
		JLabel timeWithOffsetLabel = new JLabel("Time w/ Offset:");
		this.add(timeWithOffsetLabel, gbc);

		// Create label that displays Unix time with defined offset
		currentUnixTimeWithOffsetLabel = new JLabel("");
		gbc.gridx = 1;
		gbc.gridy = row;
		this.add(currentUnixTimeWithOffsetLabel,gbc);

		// Next row!
		row++;

		// Create static label
		gbc.gridx = 0;
		gbc.gridy = row;
		JLabel timezoneLabel = new JLabel("Timezone:");
		this.add(timezoneLabel, gbc);

		// Create selector for timezone
		String[] timezones = TimeZone.getAvailableIDs();
		JComboBox<String> timezoneSelector = new JComboBox<>(timezones);
		timezoneSelector.setSelectedItem(main.selectedTimezone);
		timezoneSelector.addActionListener(new ActionListener() {
		    @Override
		    public void actionPerformed(ActionEvent e) {
		        String value = (String) timezoneSelector.getSelectedItem();
		        main.selectedTimezone = value;
		        main.persist.setString("selectedTimezone", value);
		    }
		});
		gbc.gridx = 1;
		gbc.gridy = row;
		this.add(timezoneSelector, gbc);


		// Next row!
		row++;

		// Create static label
		JLabel timestampLabel = new JLabel("Timestamp Format:");
		gbc.gridx = 0;
		gbc.gridy = row;
		this.add(timestampLabel, gbc);

		// Create text field for timestamp format
		JTextField textField = new JTextField(main.selectedDateFormat, 20);
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

		    }
		});
		gbc.gridx = 1;
		gbc.gridy = row;
		this.add(textField, gbc);

		// Next row!
		row++;

		// Create static label
		gbc.gridx = 0;
		gbc.gridy = row;
		JLabel timneStampLabel = new JLabel("Timestamp w/ Offset:");
		this.add(timneStampLabel, gbc);

		// Create label that displays current timestamp
		currentTimeStampLabel = new JLabel("");
		gbc.gridx = 1;
		gbc.gridy = row;
		this.add(currentTimeStampLabel, gbc);


	}

	// Timer which updates Unix time and timestamps values for a live view
	public void startTimer() {
            this.timer = new Timer(1000, new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                Instant offsetTime = main.getCurrentInstantWithOffset();
                long unixTimeWithOffset = offsetTime.getEpochSecond();
                Instant now = Instant.now();
                long unixTimeNow = now.getEpochSecond();

                currentUnixTimeWithOffsetLabel.setText(Long.toString(unixTimeWithOffset));
                currentUnixTimeLabel.setText(Long.toString(unixTimeNow));

                Date dateWithOffset = Date.from(offsetTime);
                String timeStamp = main.formatDate(dateWithOffset);

                Color color = timeStamp == null ? Color.RED : Color.BLACK;

                updateTimestampLabel(timeStamp == null ? "Invalid Timestamp Format" : timeStamp, color);

                if (timeStamp != null) {
                	currentTimeStampLabel.setText(timeStamp);
                }


              }
           });
           timer.start();
       }


	// Stop the timer to clean up resources
	public void stopTimer() {
	   timer.stop();
	}


	// Run when user updates the timestamp format text field. Check if they enter an invalid value
	private void updateDateFormat(String dateFormat)
	{
		main.selectedDateFormat = dateFormat;
		main.persist.setString("selectedDateFormat",dateFormat);
		String formatedDate = main.formatDate(new Date());
		Color color = formatedDate == null ? Color.RED : Color.BLACK;
		String text = formatedDate == null ? "Invalid Timestamp Format" : formatedDate;
		updateTimestampLabel(text, color);
	}

	// Run when user updates the offset text field. Numeric filter already in place, convert string to int
	private void updateOffset(String text)
	{
		try {
		    int value = Integer.parseInt(text);
		    main.selectedOffsetValue = value;
		    main.persist.setInteger("selectedOffsetValue",value);
		} catch (NumberFormatException e) {
		    main.selectedOffsetValue = 0;
		    main.persist.setInteger("selectedOffsetValue",0);
		}
	}

	// Update timstamp label with text and color (indicates error)
	private void updateTimestampLabel(String text, Color color)
	{
		currentTimeStampLabel.setForeground(color);
		currentTimeStampLabel.setText(text);
	}

}
