import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class SignInDto {
  @IsEmail({}, { message: 'Invalid email format' }) // Custom error message for better clarity
  @IsNotEmpty({ message: 'Email cannot be empty' }) // Custom error message for clarity
  email: string;

  @IsString({ message: 'Password must be a string' }) // Custom error message for better clarity
  @IsNotEmpty({ message: 'Password cannot be empty' }) // Custom error message for clarity
  password: string;
}
