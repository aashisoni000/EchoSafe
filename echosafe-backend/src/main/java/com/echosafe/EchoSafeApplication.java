package com.echosafe;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.annotation.Payload;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.socket.config.annotation.*;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@SpringBootApplication
public class EchoSafeApplication {
    public static void main(String[] args) {
        SpringApplication.run(EchoSafeApplication.class, args);
    }
}

// ============================================
// Configuration
// ============================================
@Configuration
@EnableWebSocketMessageBroker
class WebSocketConfig implements WebSocketMessageBrokerConfigurer {
    @Override
    public void configureMessageBroker(MessageBrokerRegistry config) {
        config.enableSimpleBroker("/topic", "/queue");
        config.setApplicationDestinationPrefixes("/app");
    }

    @Override
    public void registerStompEndpoints(StompEndpointRegistry registry) {
        registry.addEndpoint("/ws").setAllowedOriginPatterns("*").withSockJS();
    }
}

@Configuration
class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.cors().and().csrf().disable()
            .authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOriginPatterns(Arrays.asList("*"));
        configuration.setAllowedMethods(Arrays.asList("*"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}

// ============================================
// In-Memory Data Store
// ============================================
class DataStore {
    static Map<String, User> users = new ConcurrentHashMap<>();
    static List<Message> messages = new ArrayList<>();
    
    static {
        // Initialize demo users
        PasswordEncoder encoder = new BCryptPasswordEncoder();
        users.put("aashisoni", new User("demo", "aashisoni", encoder.encode("1234"), "Aashi Soni", "AS"));
        users.put("ishan", new User("user1", "ishan", encoder.encode("pass1"), "Ishan Patel", "IP"));
        users.put("naisha", new User("user2", "naisha", encoder.encode("pass2"), "Naisha Khan", "NK"));
        users.put("rohit", new User("user3", "rohit", encoder.encode("pass3"), "Rohit Mehta", "RM"));
        users.put("manisha", new User("user4", "manisha", encoder.encode("pass4"), "Manisha Singh", "MS"));
        users.put("sachin", new User("user5", "sachin", encoder.encode("pass5"), "Sachin Sharma", "SS"));
        users.put("devika", new User("user6", "devika", encoder.encode("pass6"), "Devika Rao", "DR"));
    }
}

// ============================================
// Models
// ============================================
class User {
    String userId, username, password, displayName, avatar;
    boolean online;
    LocalDateTime lastSeen;
    
    User(String userId, String username, String password, String displayName, String avatar) {
        this.userId = userId;
        this.username = username;
        this.password = password;
        this.displayName = displayName;
        this.avatar = avatar;
        this.online = false;
        this.lastSeen = LocalDateTime.now();
    }
}

class Message {
    Long id;
    String senderId, receiverId, type, content, fileName, fileSize, fileUrl;
    boolean ephemeral, otv, delivered, read;
    LocalDateTime timestamp, expiresAt;
    
    Message() {
        this.id = System.currentTimeMillis();
        this.timestamp = LocalDateTime.now();
    }
}

// ============================================
// DTOs
// ============================================
class AuthRequest {
    public String username, password;
}

class AuthResponse {
    public String userId, username, displayName, avatar, token, message;
    
    AuthResponse(String userId, String username, String displayName, String avatar, String token, String message) {
        this.userId = userId;
        this.username = username;
        this.displayName = displayName;
        this.avatar = avatar;
        this.token = token;
        this.message = message;
    }
}

class MessageDTO {
    public Long id;
    public String senderId, receiverId, type, content, fileName, fileSize, fileUrl, time;
    public boolean ephemeral, otv, isMe;
}

class ContactDTO {
    public String id, name, avatar, lastMessage, lastMessageTime;
    public boolean online;
    
    ContactDTO(String id, String name, String avatar, boolean online) {
        this.id = id;
        this.name = name;
        this.avatar = avatar;
        this.lastMessage = "Hello!";
        this.lastMessageTime = "20:00";
        this.online = online;
    }
}

class WebRTCSignal {
    public String type, sessionId, senderId, receiverId, sdp, candidate;
}

// ============================================
// REST Controllers
// ============================================
@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
class ApiController {
    private final PasswordEncoder passwordEncoder;
    private final DateTimeFormatter timeFormatter = DateTimeFormatter.ofPattern("HH:mm");
    
    ApiController(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }
    
    @PostMapping("/auth/login")
    public AuthResponse login(@RequestBody AuthRequest request) {
        User user = DataStore.users.get(request.username);
        if (user != null && passwordEncoder.matches(request.password, user.password)) {
            user.online = true;
            user.lastSeen = LocalDateTime.now();
            return new AuthResponse(user.userId, user.username, user.displayName, 
                                   user.avatar, "token-" + user.userId, "Login successful");
        }
        throw new RuntimeException("Invalid credentials");
    }
    
    @PostMapping("/auth/logout")
    public Map<String, String> logout(@RequestParam String userId) {
        DataStore.users.values().stream()
            .filter(u -> u.userId.equals(userId))
            .findFirst()
            .ifPresent(u -> u.online = false);
        return Map.of("message", "Logged out");
    }
    
    @GetMapping("/contacts")
    public List<ContactDTO> getContacts(@RequestParam String userId) {
        List<ContactDTO> contacts = new ArrayList<>();
        for (User user : DataStore.users.values()) {
            if (!user.userId.equals(userId)) {
                contacts.add(new ContactDTO(user.userId, user.displayName, user.avatar, user.online));
            }
        }
        return contacts;
    }
    
    @PostMapping("/messages/send")
    public MessageDTO sendMessage(@RequestBody MessageDTO dto) {
        Message msg = new Message();
        msg.senderId = dto.senderId;
        msg.receiverId = dto.receiverId;
        msg.type = dto.type;
        msg.content = dto.content;
        msg.fileName = dto.fileName;
        msg.fileSize = dto.fileSize;
        msg.fileUrl = dto.fileUrl;
        msg.ephemeral = dto.ephemeral;
        msg.otv = dto.otv;
        msg.delivered = false;
        msg.read = false;
        
        if (msg.ephemeral) {
            msg.expiresAt = msg.timestamp.plusSeconds(8);
        }
        
        DataStore.messages.add(msg);
        
        dto.id = msg.id;
        dto.time = msg.timestamp.format(timeFormatter);
        return dto;
    }
    
    @GetMapping("/messages/conversation")
    public List<MessageDTO> getConversation(@RequestParam String userId1, @RequestParam String userId2) {
        List<MessageDTO> result = new ArrayList<>();
        
        for (Message msg : DataStore.messages) {
            if ((msg.senderId.equals(userId1) && msg.receiverId.equals(userId2)) ||
                (msg.senderId.equals(userId2) && msg.receiverId.equals(userId1))) {
                
                // Skip expired ephemeral messages
                if (msg.ephemeral && msg.expiresAt != null && LocalDateTime.now().isAfter(msg.expiresAt)) {
                    continue;
                }
                
                MessageDTO dto = new MessageDTO();
                dto.id = msg.id;
                dto.senderId = msg.senderId;
                dto.receiverId = msg.receiverId;
                dto.type = msg.type;
                dto.content = msg.content;
                dto.fileName = msg.fileName;
                dto.fileSize = msg.fileSize;
                dto.fileUrl = msg.fileUrl;
                dto.ephemeral = msg.ephemeral;
                dto.otv = msg.otv;
                dto.time = msg.timestamp.format(timeFormatter);
                dto.isMe = msg.senderId.equals(userId1);
                
                result.add(dto);
            }
        }
        
        return result;
    }
    
    @GetMapping("/health")
    public Map<String, String> health() {
        return Map.of("status", "UP", "service", "EchoSafe Backend", "version", "1.0.0");
    }
}

// ============================================
// WebSocket Controller
// ============================================
@Controller
class WebSocketController {
    private final SimpMessagingTemplate messagingTemplate;
    private final DateTimeFormatter timeFormatter = DateTimeFormatter.ofPattern("HH:mm");
    
    WebSocketController(SimpMessagingTemplate messagingTemplate) {
        this.messagingTemplate = messagingTemplate;
    }
    
    @MessageMapping("/message.send")
    public void sendMessage(@Payload MessageDTO dto) {
        Message msg = new Message();
        msg.senderId = dto.senderId;
        msg.receiverId = dto.receiverId;
        msg.type = dto.type;
        msg.content = dto.content;
        msg.fileName = dto.fileName;
        msg.fileSize = dto.fileSize;
        msg.fileUrl = dto.fileUrl;
        msg.ephemeral = dto.ephemeral;
        msg.otv = dto.otv;
        msg.delivered = false;
        msg.read = false;
        
        if (msg.ephemeral) {
            msg.expiresAt = msg.timestamp.plusSeconds(8);
        }
        
        DataStore.messages.add(msg);
        
        dto.id = msg.id;
        dto.time = msg.timestamp.format(timeFormatter);
        
        // Send to receiver
        messagingTemplate.convertAndSendToUser(dto.receiverId, "/queue/messages", dto);
    }
    
    @MessageMapping("/webrtc.signal")
    public void handleWebRTC(@Payload WebRTCSignal signal) {
        messagingTemplate.convertAndSendToUser(signal.receiverId, "/queue/webrtc", signal);
    }
}