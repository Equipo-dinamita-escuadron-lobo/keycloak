package com.security.keycloak.service;

import java.util.List;

import com.security.keycloak.dtos.UserDTO;

public interface IUserKeycloakService {
    List<UserDTO> findUserByEmail(String email);
    List<UserDTO> findAllUsers();
    List<UserDTO> findUserByUsername(String username);
    UserDTO findUserById(String userId);
    UserDTO createUser(UserDTO userDTO, String role);
    void deleteUser(String userId);
    UserDTO updateUser(String userId, UserDTO userDTO);
    List<String> getRoles();
}
