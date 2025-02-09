import { SignInDto } from '../dto/signin-dto';
import {
  Injectable,
  RequestTimeoutException,
  UnauthorizedException,
} from '@nestjs/common';
import { HashingProvider } from './hashing.provider';
import { GenerateTokentProvider } from './generate-tokens.provider';

@Injectable()
export class SignInProvider {
  constructor(
    private readonly hashingProvider: HashingProvider,
    private readonly generateTokenProvider: GenerateTokentProvider,
  ) {}

  public async signIn(signInDto: SignInDto): Promise<{ accessToken: string }> {
    try {
      const { email, password } = signInDto;

      // Add the query for getting the user in database
      const user = { password: 'test password' };
      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      const passwordMatches = await this.verifyPassword(
        password,
        user.password,
      );

      if (!passwordMatches) {
        throw new UnauthorizedException('Password does not match');
      }

      return await this.generateTokenProvider.generateTokens(user);
    } catch (error) {
      throw new RequestTimeoutException(error);
    }
  }

  public async verifyPassword(
    password: string,
    hash: string,
  ): Promise<boolean> {
    try {
      return await this.hashingProvider.comparePassword(password, hash);
    } catch (error) {
      throw new RequestTimeoutException(error, {
        description: 'Password comparison failed',
      });
    }
  }
}
