package com.sazibeng.SpringBootSecurityWithJwt.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class Token {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private  String token;
    @Column(name = "is_log_out")
    private Boolean isLogout;

    @ManyToOne
    @JoinColumn(name = "user_id")
    private  User user;


}
