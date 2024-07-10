package com.example.oauthjwt.service;

import com.example.oauthjwt.dto.CustomOauth2User;
import com.example.oauthjwt.dto.GoogleResponse;
import com.example.oauthjwt.dto.NaverResponse;
import com.example.oauthjwt.dto.Oauth2Response;
import com.example.oauthjwt.dto.UserDTO;
import com.example.oauthjwt.entity.User;
import com.example.oauthjwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomOauth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        OAuth2User oAuth2User = super.loadUser(userRequest);
        log.info("oAuth2User={}" , oAuth2User);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        Oauth2Response oauth2Response = null;

        if (registrationId.equals("naver")) {
            oauth2Response = new NaverResponse(oAuth2User.getAttributes());
        }

        else if (registrationId.equals("google")) {
            oauth2Response = new GoogleResponse(oAuth2User.getAttributes());
        }

        else {
            return null;
        }

        String username = oauth2Response.getProvider() + " " + oauth2Response.getProviderId();

        User findUser = userRepository.findByUsername(username);

        if (findUser == null) {

            User user = new User();
            user.setUsername(username);
            user.setName(oauth2Response.getName());
            user.setRole("ROLE_USER");

            userRepository.save(user);

            UserDTO userDTO = new UserDTO();
            userDTO.setUsername(username);
            userDTO.setName(oauth2Response.getName());
            userDTO.setRole("ROLE_USER");

            return new CustomOauth2User(userDTO);
        }

        else { // exist data (굳이 필요한가?)

            findUser.setEmail(oauth2Response.getEmail());
            findUser.setName(oauth2Response.getName());

            userRepository.save(findUser);

            UserDTO userDTO = new UserDTO();
            userDTO.setUsername(findUser.getUsername());
            userDTO.setName(oauth2Response.getName());
            userDTO.setRole(findUser.getRole());

            return new CustomOauth2User(userDTO);
        }

    }
}
