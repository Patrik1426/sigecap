import { TRPCError } from "@trpc/server";
import { z } from "zod";
import { randomBytes } from "crypto";
import { hashPassword, verifyPassword, generateToken } from "./auth";
import {
  getUserByEmail,
  createUser,
  crearServidor,
  crearTokenRestablecimiento,
  obtenerTokenRestablecimiento,
  actualizarPasswordUsuario,
  marcarTokenComoUsado,
} from "./db";
import { COOKIE_NAME } from "../shared/const";
import { router, publicProcedure, protectedProcedure } from "./trpc";
import { servidoresRouter } from "./routers/servidores";
import { usuariosRouter } from "./routers/usuarios";
import { importacionRouter } from "./routers/importacion";
import { perfilRouter } from "./routers/perfil";
import { cursosRouter } from "./routers/cursos";
import { institucionesRouter } from "./routers/instituciones";
import { solicitudesRouter } from "./routers/solicitudes";

export { router, publicProcedure };

const authRouter = router({
  register: publicProcedure
    .input(
      z.object({
        nombre: z.string().min(2),
        email: z.string().email(),
        password: z.string().min(8),
      }),
    )
    .mutation(async ({ input }) => {
      const existing = await getUserByEmail(input.email);
      if (existing) {
        throw new TRPCError({
          code: "CONFLICT",
          message: "Email ya registrado",
        });
      }
      const hash = await hashPassword(input.password);
      const id = await createUser({
        nombre: input.nombre,
        email: input.email,
        passwordHash: hash,
        role: "user",
      });
      await crearServidor({
        userId: id,
        nombreCompleto: input.nombre,
        rfc: `UREG${String(id).padStart(9, "0")}`,
        curp: `UREG${String(id).padStart(14, "0")}`,
        cargo: "Por definir",
        dependencia: "Por definir",
        nivel: "federal",
        grupoFuncion: "ADMO",
        fechaIngreso: new Date(),
        datosContacto: input.email,
        upa: null,
        cmao: null,
        ua: null,
        nivelProgresion: 0,
        estatus: "activo",
        creadoPor: id,
        actualizadoPor: id,
      });
      return { success: true, id };
    }),

  login: publicProcedure
    .input(z.object({ email: z.string().email(), password: z.string(), rememberMe: z.boolean().optional() }))
    .mutation(async ({ ctx, input }) => {
      const user = await getUserByEmail(input.email);
      if (
        !user ||
        !(await verifyPassword(input.password, user.passwordHash))
      ) {
        throw new TRPCError({
          code: "UNAUTHORIZED",
          message: "Credenciales invalidas",
        });
      }
      if (!user.isActive) {
        throw new TRPCError({
          code: "FORBIDDEN",
          message: "Tu cuenta ha sido desactivada. Contacta al administrador.",
        });
      }
      const token = generateToken(user);
      const cookieOpts: any = {
        httpOnly: true,
        sameSite: "lax" as const,
      };
      if (input.rememberMe) {
        cookieOpts.maxAge = 30 * 24 * 60 * 60 * 1000;
      }
      ctx.res.cookie(COOKIE_NAME, token, cookieOpts);
      return {
        success: true,
        user: {
          id: user.id,
          nombre: user.nombre,
          email: user.email,
          role: user.role,
        },
      };
    }),

  me: publicProcedure.query(({ ctx }) => ctx.user ?? null),

  logout: publicProcedure.mutation(({ ctx }) => {
    ctx.res.clearCookie(COOKIE_NAME);
    return { success: true };
  }),

  solicitarRestablecimiento: publicProcedure
    .input(z.object({ email: z.string().email() }))
    .mutation(async ({ input }) => {
      const user = await getUserByEmail(input.email);
      if (!user) return { success: true }; // don't reveal if user exists
      const token = randomBytes(32).toString("hex");
      await crearTokenRestablecimiento(
        user.id,
        token,
        new Date(Date.now() + 24 * 60 * 60 * 1000),
      );
      // TODO: send email with reset link
      return { success: true };
    }),

  restablecerContrasena: publicProcedure
    .input(z.object({ token: z.string(), password: z.string().min(8) }))
    .mutation(async ({ input }) => {
      const record = await obtenerTokenRestablecimiento(input.token);
      if (!record || record.usedAt || new Date() > record.expiresAt) {
        throw new TRPCError({
          code: "BAD_REQUEST",
          message: "Token invalido o expirado",
        });
      }
      const hash = await hashPassword(input.password);
      await actualizarPasswordUsuario(record.userId, hash);
      await marcarTokenComoUsado(record.id);
      return { success: true };
    }),
});

export const appRouter = router({
  auth: authRouter,
  servidores: servidoresRouter,
  usuarios: usuariosRouter,
  importacion: importacionRouter,
  perfil: perfilRouter,
  cursos: cursosRouter,
  instituciones: institucionesRouter,
  solicitudes: solicitudesRouter,
});

export type AppRouter = typeof appRouter;
