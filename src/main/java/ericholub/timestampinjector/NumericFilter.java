package ericholub.timestampinjector;

import javax.swing.text.DocumentFilter;
import javax.swing.text.BadLocationException;
import javax.swing.text.AttributeSet;

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
