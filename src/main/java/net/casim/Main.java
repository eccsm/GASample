package net.casim;

import com.google.zxing.WriterException;
import net.casim.utils.HttpServerBuilder;

import java.io.IOException;

public class Main {
    public static void main(String[] args) throws IOException, WriterException {
        HttpServerBuilder.startServer();

        System.out.println("Server is running. Open your browser and go to http://localhost:8080 to access the application.");

    }
}