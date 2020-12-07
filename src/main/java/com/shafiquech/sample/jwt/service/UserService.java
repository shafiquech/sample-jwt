package com.shafiquech.sample.jwt.service;

import java.util.Collections;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserService implements UserDetailsService {


  @Override
  public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {

    //get user from DB and perform checks

    return new User("admin", "admin", Collections.EMPTY_LIST);
  }
}
