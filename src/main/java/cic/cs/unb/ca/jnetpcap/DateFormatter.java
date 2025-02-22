package cic.cs.unb.ca.jnetpcap;

import java.text.SimpleDateFormat;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Date;

public class DateFormatter {

    public static String parseDateFromLong(long time, String format) {
        try {
            if (format == null) {
                format = "dd/MM/yyyy hh:mm:ss";
            }
            SimpleDateFormat simpleFormatter = new SimpleDateFormat(format);
            Date tempDate = new Date(time);
            return simpleFormatter.format(tempDate);
        } catch (Exception ex) {
            System.out.println(ex.toString());
            return "dd/MM/yyyy hh:mm:ss";
        }
    }

    public static String convertMilliseconds2String(long time, String format) {

        if (format == null) {
            format = "dd/MM/yyyy hh:mm:ss";
        }

        DateTimeFormatter formatter = DateTimeFormatter.ofPattern(format)
                .withLocale(java.util.Locale.ENGLISH); // Force English locale to avoid Chinese characters
        LocalDateTime ldt = LocalDateTime.ofInstant(Instant.ofEpochMilli(time), ZoneId.systemDefault());
        return new String(ldt.format(formatter).getBytes(java.nio.charset.StandardCharsets.UTF_8)); // Ensure UTF-8
                                                                                                    // encoding
    }

}
