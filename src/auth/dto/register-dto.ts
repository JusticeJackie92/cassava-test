import {
  IsAlphanumeric,
  IsEmail,
  isNotEmpty,
  IsNotEmpty,
  IsString,
  isString,
  Length,
} from 'class-validator';

export class RegisterUserDto {
  @IsEmail()
  public email: string;

  @IsAlphanumeric()
  @IsNotEmpty()
  @IsString()
  username: string;

  @IsNotEmpty()
  @IsString()
  @Length(5, 20, {
    message: 'Password Must be between 5 to 20 characters long',
  })
  public password: string;

  @IsNotEmpty()
  @IsString()
  @Length(5, 20, {
    message: 'Password Must be between 5 to 20 characters long',
  })
  public confirmHashPassword: string;
}
