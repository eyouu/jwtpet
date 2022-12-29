package com.whosaidmeow.jwtpet.model;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.NaturalId;

import java.util.Set;

import static jakarta.persistence.FetchType.EAGER;
import static lombok.AccessLevel.PRIVATE;

@Entity
@Data
@Table(name = "user_principal")
@AllArgsConstructor
@NoArgsConstructor
public class User {

    @Id
    @GeneratedValue
    private Long id;
    private String name;
    @NaturalId
    @Column(unique = true)
    private String username;
    private String password;

    @Setter(PRIVATE)
    @ManyToMany(fetch = EAGER)
    private Set<Role> roles;
}
