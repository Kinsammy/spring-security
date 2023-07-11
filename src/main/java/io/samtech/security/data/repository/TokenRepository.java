package io.samtech.security.data.repository;

import io.samtech.security.data.models.token.Token;
import io.samtech.security.data.models.user.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface TokenRepository  extends JpaRepository<Token, Long> {

    @Query("""
select t from Token t inner join User u on t.user.Id = u.Id
where u.Id = :userId and (t.expired = false or t.revoked= false)    \s
"""
    )
    List<Token> findAllValidTokensByUserId(Long userId);
    Optional<Token> findTokenByUser(User user);


    Optional<Token> findByToken(String  token);

    Optional<Token> findTokenByUserAndToken(User user, String otp);

}
