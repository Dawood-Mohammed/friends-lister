package com.example.friendslister;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Controller;
import org.springframework.stereotype.Repository;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.filter.OncePerRequestFilter;
import sun.plugin.liveconnect.SecurityContextHelper;

import javax.persistence.*;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.transaction.Transactional;
import java.io.IOException;
import java.io.Serializable;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@SpringBootApplication
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class FriendsListerApplication {
	private final FriendRepo friendRepo;
	private final AppUserRepo appUserRepo;

	@GetMapping("/friends")
	public List<Friend> getFriends(){
		System.out.println("loading friends ..............");
		return friendRepo.findAll();
	}

	@GetMapping("/token/refresh")
	@ResponseBody
	public void refreshToken(HttpServletRequest request, HttpServletResponse response)throws Exception{
		String auth = request.getHeader(HttpHeaders.AUTHORIZATION);
		if(auth != null && auth.startsWith("Bearer ")){
			try{
				String refresh_token = auth.substring("Bearer ".length());
				Algorithm alg = Algorithm.HMAC256("algkey".getBytes());
				DecodedJWT decodedJWT = JWT.require(alg).build().verify(refresh_token);
				String username = decodedJWT.getSubject();
				AppUser user = appUserRepo.findAppUserByEmail(username);
				List<String> authorities = user.getRoles().stream().map(Role::getName).collect(Collectors.toList());
				String access_token = JWT.create()
						.withSubject(username)
						.withExpiresAt(new Date(System.currentTimeMillis() + 5 * 60 * 1000))
						.withIssuer(request.getRequestURL().toString())
						.withClaim("roles",authorities)
						.sign(alg);
				Map<String, String> tokens = new HashMap<>();
				tokens.put("access_token", access_token);
				tokens.put("refresh_token", refresh_token);
				response.setContentType(MediaType.APPLICATION_JSON_VALUE);
				new ObjectMapper().writeValue(response.getOutputStream(), tokens);
			}catch(Exception ex){
				response.setHeader("error", ex.getMessage());
				response.setStatus(HttpStatus.FORBIDDEN.value());
				Map<String , String> error = new HashMap<>();
				error.put("error_message", ex.getMessage());
				response.setContentType(MediaType.APPLICATION_JSON_VALUE);
				new ObjectMapper().writeValue(response.getOutputStream(), error);
			}
		}else{
			throw new RuntimeException("invalid token");
		}
	}

	public static void main(String[] args) {
		SpringApplication.run(FriendsListerApplication.class, args);
	}

	@Bean
	PasswordEncoder passwordEncoder(){
		return new BCryptPasswordEncoder();
	}
	@Bean
	CommandLineRunner clr(AppUserService userService, FriendRepo friendRepo){
		return args -> {
			Role roleUser = userService.saveRole(new Role(null,"ROLE_USER"));
			Role roleAdmin = userService.saveRole(new Role(null,"ROLE_ADMIN"));
			AppUser user = userService.savaAppUser(new AppUser(null,"dawood","dawood@example.com","david", true, new ArrayList<Role>()));
			userService.addRoleToUser(user.getEmail(), roleUser.getName());
			friendRepo.save(new Friend(null, "ahmed ali", "software engineer"));
			friendRepo.save(new Friend(null, "hamid alsadig", "mobile developer"));
			friendRepo.save(new Friend(null, "mohammed azhary", "web developer"));
			friendRepo.save(new Friend(null, "anas mohammed", "desktop developer"));
		};
	}
}
//security config
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
class SecurityConfig extends WebSecurityConfigurerAdapter{
	private final UserDetailsService userDetailsService;
	private final PasswordEncoder passwordEncoder;
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userDetailsService)
				.passwordEncoder(passwordEncoder);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable()
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
				.and()
				.authorizeRequests().antMatchers("/login/**","/api/token/refresh/**").permitAll()
				.antMatchers(HttpMethod.GET,"/api/friends/**").hasRole("USER")
				.anyRequest().authenticated()
				.and()
				.addFilter(new UsernamePasswordAuthenticationFilter(){
					@Override
					public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
						try {
							return authenticationManagerBean().authenticate(new UsernamePasswordAuthenticationToken(request.getParameter("email"),request.getParameter("password")));
						} catch (Exception e) {
							e.printStackTrace();
						}
						return null;
					}

					@Override
					protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
						User user = (User)authResult.getPrincipal();
						Algorithm alg = Algorithm.HMAC256("algkey".getBytes());
						String accessToken = JWT.create()
								.withSubject(user.getUsername())
								.withExpiresAt(new Date(System.currentTimeMillis()+ 1 * 60 * 1000))
								.withIssuer(request.getRequestURL().toString())
								.withClaim("roles", user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
								.sign(alg);
						String refreshToken = JWT.create()
								.withSubject(user.getUsername())
								.withExpiresAt(new Date(System.currentTimeMillis()+ 5 * 60 * 60 * 1000))
								.withIssuer(request.getRequestURL().toString())
								.sign(alg);
						Map<String,String> tokens = new HashMap<>();
						tokens.put("access_token", accessToken);
						tokens.put("refresh_token", refreshToken);
						response.setContentType(MediaType.APPLICATION_JSON_VALUE);
						new ObjectMapper().writeValue(response.getOutputStream(), tokens);
					}
				})
				.addFilterBefore(new OncePerRequestFilter() {
					@Override
					protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
						if (request.getServletPath().equals("/login") || request.getServletPath().equals("/api/token/refresh")) {
							filterChain.doFilter(request, response);
						} else {
							String auth = request.getHeader(HttpHeaders.AUTHORIZATION);
							if(auth != null && auth.startsWith("Bearer ")){
								try{
									String token = auth.substring("Bearer ".length());
									Algorithm alg = Algorithm.HMAC256("algkey".getBytes());
									DecodedJWT decodedJWT = JWT.require(alg).build().verify(token);
									String user = decodedJWT.getSubject();
									String[] roles = decodedJWT.getClaim("roles").asArray(String.class);
									List<GrantedAuthority> authorities = Stream.of(roles).map(SimpleGrantedAuthority::new).collect(Collectors.toList());
									SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(user, null, authorities));
									filterChain.doFilter(request, response);
								}catch(Exception ex){
									response.setHeader("error", ex.getMessage());
									response.setStatus(HttpStatus.FORBIDDEN.value());
									Map<String, String> error = new HashMap<>();
									error.put("error_message", ex.getMessage());
									response.setContentType(MediaType.APPLICATION_JSON_VALUE);
									new ObjectMapper().writeValue(response.getOutputStream(), error);
								}
							}else{
								filterChain.doFilter(request, response);
							}
						}
					}
				}, UsernamePasswordAuthenticationFilter.class);
	}

	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}
}

//friends app dao
@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
class Friend implements Serializable {
	@Id
	@GeneratedValue
	private Long id;
	private String name;
	private String job;
}
@Repository
interface FriendRepo extends JpaRepository<Friend, Long> {}
@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
class AppUser implements Serializable{
	@Id
	@GeneratedValue
	private Long id;
	private String name;
	private String email;
	private String password;
	private Boolean enabled;
	@OneToMany
	@JoinColumn(name = "user_id")
	private List<Role> roles = new ArrayList<Role>();

}
@Repository
interface AppUserRepo extends JpaRepository<AppUser, Long>{
	AppUser findAppUserByEmail(String email);
}
@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
class Role implements Serializable{
	@Id
	@GeneratedValue
	private Long id;
	private String name;
}
@Repository
interface RoleRepo extends JpaRepository<Role, Long>{Role findByName(String roleName);}
@Service
@RequiredArgsConstructor
@Transactional
class AppUserService implements UserDetailsService {
	private final AppUserRepo appUserRepo;
	private final RoleRepo roleRepo;
	private final PasswordEncoder passwordEncoder;

	public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
		AppUser appUser = appUserRepo.findAppUserByEmail(email);
		if(appUser == null){
			throw new UsernameNotFoundException("user not found");
		}
		List<GrantedAuthority> authorities = appUser.getRoles().stream()
				.map(role -> new SimpleGrantedAuthority(role.getName()))
				.collect(Collectors.toList());
		return  new User(appUser.getEmail(),appUser.getPassword(),appUser.getEnabled(),appUser.getEnabled(),appUser.getEnabled(),appUser.getEnabled(),authorities);
	}
	public List<AppUser> getAppUsers(){
		return appUserRepo.findAll();
	}
	public AppUser getAppUser(Long id){
		return appUserRepo.findById(id).get();
	}
	public AppUser savaAppUser(AppUser appUser){
		appUser.setPassword(passwordEncoder.encode(appUser.getPassword()));
		return appUserRepo.save(appUser);
	}
	public void deleteAppUser(Long id){
		appUserRepo.deleteById(id);
	}
	public void addRoleToUser(String userName, String roleName){
		AppUser user = appUserRepo.findAppUserByEmail(userName);
		Role role = roleRepo.findByName(roleName);
		user.getRoles().add(role);
	}
	public Role saveRole(Role role){
		return roleRepo.save(role);
	}
}