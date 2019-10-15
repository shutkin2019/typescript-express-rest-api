import * as jwt from 'jsonwebtoken';
import { NextFunction, Request, Response } from 'express';
import app from '@/config/server/server';
import HttpError from '@/config/error';
import * as http from 'http';

interface RequestWithUser extends Request {
    user: object | string;
}

/**
 *
 * @param {RequestWithUser} req
 * @param {Response} res
 * @param {NextFunction} next
 * @returns {void}
 * @swagger
 *  components:
 *   securitySchemes:
 *     bearerAuth:
 *       type: http
 *       scheme: bearer
 *       bearerFormat: JWT
 */
export function isAuthenticated(req: RequestWithUser, res: Response, next: NextFunction): void {
    const token: any = req.headers.authorization;

    if (token && token.indexOf('Bearer ') !== -1) {
        try {
            const user: object | string = jwt.verify(token.split('Bearer ')[1], app.get('secret'));

            req.user = user;

            return next();
        } catch (error) {
            return next(new HttpError(401, http.STATUS_CODES[401]));
        }
    }

    return next(new HttpError(400, 'No token provided'));
}
