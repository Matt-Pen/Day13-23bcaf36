package in.edu.kristujayanti.services;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.Projections;
import com.mongodb.client.model.Updates;
import com.mongodb.client.result.DeleteResult;
import com.mongodb.client.result.InsertOneResult;
import com.mongodb.client.result.UpdateResult;
import in.edu.kristujayanti.secretclass;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServer;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;
import jakarta.activation.DataHandler;
import jakarta.activation.DataSource;
import jakarta.mail.*;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeBodyPart;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.util.ByteArrayDataSource;
import jakarta.mail.internet.MimeMultipart;
import org.bson.Document;
import org.bson.conversions.Bson;
import com.google.zxing.qrcode.QRCodeWriter;
import redis.clients.jedis.Jedis;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class SampleService {
    Jedis jedis = new Jedis("localhost", 6379);
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    secretclass srt=new secretclass();
    Vertx vertx = Vertx.vertx();
    HttpServer server = vertx.createHttpServer();
    String connectionString = srt.constr;
    MongoClient mongoClient = MongoClients.create(connectionString);
    MongoDatabase database = mongoClient.getDatabase("To-do-list");
    MongoCollection<Document> users = database.getCollection("Users");
    MongoCollection<Document> tasks = database.getCollection("tasks");
    DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd-MM-yyyy");

    public void usersign(RoutingContext ctx) {
        //some more git test
        JsonObject signin = ctx.getBodyAsJson();
        String user = signin.getString("email");
        String name = signin.getString("name");

        ctx.response().setChunked(true);
        Document docs=users.find().filter(Filters.eq("email",user)).first();

        if(docs!=null) {
            ctx.response().write("Email already registered");
        }
        else {
            ctx.response().write("Password has been sent to your Email\n" + "Login using the password that has been sent");
            String pwd = generateID(8);
            sendemail(pwd, user);

            String hashpass = hashPassword(pwd);
            Document doc = new Document("name", name).append("email", user).append("pass", hashpass);
            InsertOneResult ins = users.insertOne(doc);

            if (ins.wasAcknowledged()) {
                ctx.response().write("Signed in successfully.");

            }
        }

        ctx.response().end();
    }
    public void userlog(RoutingContext ctx) {
        JsonObject login = ctx.getBodyAsJson();
        JsonArray jarr = new JsonArray();
        String user = login.getString("email");
        String pwd = login.getString("pass");
//        String hashlog = hashit(pwd);
        String status = "";
        ctx.response().setChunked(true);

        for (Document doc : users.find()) {
            String dbuser = doc.getString("email");
            String dbpass = doc.getString("pass");

            if (dbuser.equals(user)) {
                if (verifyPassword(pwd,dbpass)) {
                    status = "Login was successfull";
                } else {
                    status = "Password is Incorrect";
                }
            } else {
                status = "Invalid Login Credentials";
            }
        }
        ctx.response().write(status + "\n");
        ctx.response().write("These are the Available events:" + "\n");
        Bson projection = Projections.fields(Projections.exclude("_id","tokens"));
        for (Document doc : tasks.find().projection(projection)) {
            jarr.add(new JsonObject(doc.toJson()));
        }

        ctx.response().end(jarr.encodePrettily());

    }
    public int resetpass(RoutingContext ctx)
    {   ctx.response().setChunked(true);
        int set=0;
        String email=ctx.request().getParam("email");
        String entoken=ctx.request().getParam("token");
        String pass=ctx.request().getParam("pass");
        if(entoken==null){
            String token=generateID(6);
            setoken(token,email);
            sendtokenemail(token,email);
            ctx.response().write("Password reset token sent to Email.\n Token only valid for 10 Minutes");
            set=1;
        }
        if(set!=1){
//            System.out.println("Received token: " + entoken);
            String tokemail=getoken(entoken);
            if(tokemail==null){
                set=1;
                ctx.response().write("Invalid token.");
            }else {
//            System.out.println("redis email"+tokemail);
                if (tokemail.equals(email) || set != 1) {
                    String hashpass = hashPassword(pass);
                    Bson filter = Filters.eq("email", email);
                    Bson update = Updates.set("pass", hashpass);
                    UpdateResult res = users.updateOne(filter, update);
                    if (res.wasAcknowledged()) {
                        ctx.response().write("Password successfully changed.");
                        deltoken(entoken);
                    }
                } else {
                    ctx.response().write("invalid token or token has expired");
                }
            }
        }
        ctx.response().end();
        return set;
    }


    public static BufferedImage generateqr(String token)throws WriterException {
        int width=300;
        int height=300;
        QRCodeWriter qrCodeWriter = new QRCodeWriter();
        Map<EncodeHintType, Object> hints = Map.of(EncodeHintType.CHARACTER_SET, "UTF-8");

        BitMatrix bitMatrix = qrCodeWriter.encode(token, BarcodeFormat.QR_CODE, width, height, hints);
        return MatrixToImageWriter.toBufferedImage(bitMatrix);
    }

//    public String hashit (String pass) {
//
//        try {
//            MessageDigest md = MessageDigest.getInstance("SHA-512");
//            byte[] hashed = md.digest(pass.getBytes());
//            StringBuilder sb = new StringBuilder();
//            for (byte b : hashed)
//                sb.append(String.format("%02x", b));
//            return sb.toString();
//
//        } catch (Exception e) {
//            throw new RuntimeException("Hashing Failed");
//        }
//    }
    public static String generateID(int length) {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder sb = new StringBuilder();
        Random random = new Random();
        for (int i = 0; i < length; i++) {
            int index = random.nextInt(chars.length());
            sb.append(chars.charAt(index));
        }

        return sb.toString();
    }

    public String hashPassword(String rawPassword) {
        return passwordEncoder.encode(rawPassword);
    }
    public boolean verifyPassword(String rawPassword, String hashedPassword) {
        return passwordEncoder.matches(rawPassword, hashedPassword);
    }

    public void sendtokenemail(String token,String email){
        String to = email;
        // provide sender's email ID
        String from = srt.from;

        // provide Mailtrap's username
        final String username = srt.username;
        final String password = srt.password;

        // provide Mailtrap's host address
        String host = "smtp.gmail.com";

        // configure Mailtrap's SMTP details
        Properties props = new Properties();
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.host", host);
        props.put("mail.smtp.port", "587");

        // create the Session object
        Session session = Session.getInstance(props,
                new Authenticator() {
                    @Override
                    protected PasswordAuthentication getPasswordAuthentication() {
                        return new PasswordAuthentication(username, password);
                    }
                });

        try {
            // create a MimeMessage object
            Message message = new MimeMessage(session);
            // set From email field
            message.setFrom(new InternetAddress(from));
            // set To email field
            message.setRecipient(Message.RecipientType.TO, new InternetAddress(to));
            // set email subject field
            message.setSubject("Use this token to reset your password");
            // set the content of the email message
            message.setText("The Token for resetting password is: "+ token+"\nToken is only valid for 10 Minutes.");

            // send the email message
            Transport.send(message);

            System.out.println("Email Message token Sent Successfully!");

        } catch (MessagingException e) {
            throw new RuntimeException(e);
        }

    }
    public void sendemail(String pass,String email){
        String to = email;
        // provide sender's email ID
        String from = srt.from;

        // provide Mailtrap's username
        final String username = srt.username;
        final String password = srt.password;

        // provide Mailtrap's host address
        String host = "smtp.gmail.com";

        // configure Mailtrap's SMTP details
        Properties props = new Properties();
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.host", host);
        props.put("mail.smtp.port", "587");

        // create the Session object
        Session session = Session.getInstance(props,
                new Authenticator() {
                    @Override
                    protected PasswordAuthentication getPasswordAuthentication() {
                        return new PasswordAuthentication(username, password);
                    }
                });

        try {
            // create a MimeMessage object
            Message message = new MimeMessage(session);
            // set From email field
            message.setFrom(new InternetAddress(from));
            // set To email field
            message.setRecipient(Message.RecipientType.TO, new InternetAddress(to));
            // set email subject field
            message.setSubject("Use this Password to login to your Student Account.");
            // set the content of the email message
            message.setText("The Auto-generated password is: "+ pass);

            // send the email message
            Transport.send(message);

            System.out.println("Email Message Sent Successfully!");

        } catch (MessagingException e) {
            throw new RuntimeException(e);
        }

    }


    public void setoken(String key, String value)
    {
        jedis.setex(key,600,value);
    }
    public String getoken(String token){
        return jedis.get(token);
    }
    public void deltoken(String key){
        jedis.del(key);
    }
    //Your Logic Goes Here
}
