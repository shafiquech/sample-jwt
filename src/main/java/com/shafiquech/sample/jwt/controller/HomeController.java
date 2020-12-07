package com.shafiquech.sample.jwt.controller;

import com.shafiquech.sample.jwt.model.JwtRequest;
import com.shafiquech.sample.jwt.model.JwtResponse;
import com.shafiquech.sample.jwt.service.UserService;
import com.shafiquech.sample.jwt.util.JWTUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@Slf4j
public class HomeController {

  private final JWTUtil jwtUtil;
  private final AuthenticationManager authenticationManager;
  private final UserService userService;


  @GetMapping
  public String home() {
    return "Welcome to my page ....";
  }

  @PostMapping("/authenticate")
  public JwtResponse authenticate(@RequestBody JwtRequest jwtRequest) throws Exception {

    authenticationToken(jwtRequest);

    final UserDetails userDetails = userService.loadUserByUsername(jwtRequest.getUsername());

    final String token = jwtUtil.generateToken(userDetails);

    return new JwtResponse(token);

  }

  private void authenticationToken(JwtRequest jwtRequest) throws Exception {
    try {

      authenticationManager.authenticate(
          new UsernamePasswordAuthenticationToken(jwtRequest.getUsername(),
              jwtRequest.getPassword()));
    } catch (BadCredentialsException badCredentialsException) {
      throw new Exception("Invalid credentials", badCredentialsException);
    }
  }

}
