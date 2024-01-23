import { Controller, ForbiddenException, Injectable } from "@nestjs/common";
import { PrismaService } from "src/prisma/prisma.service";
import { AuthDto } from "./dto";
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from "@prisma/client/runtime/library";

@Injectable()
export class AuthService {
    constructor(private prisma: PrismaService) { }

    async signup(dto: AuthDto) {
        //Generate the password hash
        const hash = await argon.hash(dto.password);
        //save the new user in the db
        try {
            const user = await this.prisma.user.create({
                data: {
                    email: dto.email,
                    hash,
                },
            });
            delete user.hash;
            //return the saved user
            return user;
        }
        catch (error) {
            if (error instanceof PrismaClientKnownRequestError) {
                if (error.code === 'P2002') {
                    throw new ForbiddenException(
                        'Credentials taken',
                    )
                }
            }
            throw error;
        }
    }

    async signin(dto: AuthDto) {
        //find user by email
        const user = await this.prisma.user.findUnique({
            where: {
                email: dto.email,
            }
        });
        //if the user does not exist throw an exception
        if(!user) throw new ForbiddenException('Credentials incorrect');
        //compare password
        const pwMAtches = await argon.verify(user.hash, dto.password);
        //if password incorrect throw an exception
        if(!pwMAtches) throw new ForbiddenException('Credentials incorrect');
        //return the user
        delete user.hash;
        return user;
    }
}   