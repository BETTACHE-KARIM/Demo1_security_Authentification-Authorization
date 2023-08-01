package com.kb.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
public class JwtService {

	
	
//	 @Value("${application.security.jwt.secret-key}")
//	  private String secretKey;
	private static final String secretKey= "/k0ltfai+Ywysjk4a17gF/doDvl1dqcNZ5DZ8hYeMu1PbIYBiaUY9i8Pyjt58liXDBKpQ2zIp1hHcf09+MYruyA9ury5cyYxn3tj0jxZIAYcxYNiiU3SfAzw1O1TMm6/1qdf5nSc3uESix3YskZPuHTITHbNnnlVrNG+1wj4ccTufO4TCD+aw+A+CaZEFIAy2XF2Y3h2mdF1tG6WxjMalhCqGj3QD05o3K181zRTP77Ezfr0bXUra3WEQdM01VsV8LRmpFrk2u1xs9L11SoQSXbhKjS3qFbVQ9I61/ZjLy+7uge1wYCxdnVVfx9qipvvuRyjsYDuwsFzQxZFVYkgRi5ezQS40RIvrT6EYBjkuCg=";
	private long jwtExpiration= 86400000 ;
	 private long refreshExpiration = 604800000 ;
	 
	
	 public String extractUsername(String token) {
		    return extractClaim(token, Claims::getSubject);
		  }

		  public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
		    final Claims claims = extractAllClaims(token);
		    return claimsResolver.apply(claims);
		  }

		  public String generateToken(UserDetails userDetails) {
		    return generateToken(new HashMap<>(), userDetails);
		  }

		  public String generateToken(
		      Map<String, Object> extraClaims,
		      UserDetails userDetails
		  ) {
		    return buildToken(extraClaims, userDetails, jwtExpiration);
		  }

		  public String generateRefreshToken(
		      UserDetails userDetails
		  ) {
		    return buildToken(new HashMap<>(), userDetails, refreshExpiration);
		  }

		  private String buildToken(
		          Map<String, Object> extraClaims,
		          UserDetails userDetails,
		          long expiration
		  ) {
		    return Jwts
		            .builder()
		            .setClaims(extraClaims)
		            .setSubject(userDetails.getUsername())
		            .setIssuedAt(new Date(System.currentTimeMillis()))
		            .setExpiration(new Date(System.currentTimeMillis() + expiration))
		            .signWith(getSignInKey(), SignatureAlgorithm.HS256)
		            .compact();
		  }

		  public boolean isTokenValid(String token, UserDetails userDetails) {
		    final String username = extractUsername(token);
		    return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
		  }

		  private boolean isTokenExpired(String token) {
		    return extractExpiration(token).before(new Date());
		  }

		  private Date extractExpiration(String token) {
		    return extractClaim(token, Claims::getExpiration);
		  }

		  private Claims extractAllClaims(String token) {
		    return Jwts
		        .parserBuilder()
		        .setSigningKey(getSignInKey())
		        .build()
		        .parseClaimsJws(token)
		        .getBody();
		  }

		  private Key getSignInKey() {
		    byte[] keyBytes = Decoders.BASE64.decode(secretKey);
		    return Keys.hmacShaKeyFor(keyBytes);
		  }
	  
	  
	  
	  
	  
	  
	  
	  
	  
	  
}
