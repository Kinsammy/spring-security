package io.samtech.security.service.serviceInterface;

import com.github.fge.jsonpatch.JsonPatch;
import io.samtech.security.data.dto.request.VerifyRequest;
import io.samtech.security.data.dto.response.ApiResponse;
import io.samtech.security.data.dto.response.AuthenticationResponse;
import io.samtech.security.data.dto.response.UploadResponse;
import io.samtech.security.data.models.user.User;
import io.samtech.security.exception.ImageUploadException;
import io.samtech.security.exception.LogicException;
import io.samtech.security.exception.RegistrationException;
import io.samtech.security.exception.UserNotFoundException;
import jakarta.validation.constraints.NotNull;
import org.springframework.data.crossstore.ChangeSetPersister;
import org.springframework.web.multipart.MultipartFile;

public interface UserService {
    User getUserByEmail(String email) throws LogicException;
    User getUserById(Long userId) throws UserNotFoundException;
    ApiResponse verifyAccount(VerifyRequest verifyRequest) throws RegistrationException, UserNotFoundException;
    void sendResetPasswordMail(String email) throws LogicException;
    AuthenticationResponse updateUser(Long userId, JsonPatch updatePayLoad);
    void updateUser(User user);
    UploadResponse uploadProfileImage(MultipartFile profileImage, Long userId) throws ImageUploadException;
    void resetPassword(String email, String otp, String newPassword) throws RegistrationException, LogicException;
    void changePassword(String email, String otp, String newPassword) throws RegistrationException, LogicException;
    void sendVerifyLink(@NotNull User user);
    void sendVerifyOtp(User user);
}
