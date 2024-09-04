package ru.userservice.mappers;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import ru.userservice.dto.UserRegisterResponse;
import ru.userservice.models.User;

@Mapper(componentModel = "spring")
public interface UserMapper {

    @Mapping(source = "username", target = "username")
    @Mapping(source = "id", target = "userId")
    UserRegisterResponse userToUserRegisterResponse(User user);
}