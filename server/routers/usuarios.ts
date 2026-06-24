import { TRPCError } from "@trpc/server";
import { z } from "zod";
import { router, adminProcedure } from "../trpc";
import { hashPassword } from "../auth";
import {
  listarUsuarios,
  cambiarRolUsuario,
  toggleActivoUsuario,
  getUserByEmail,
  createUser,
  crearServidor,
} from "../db";

export const usuariosRouter = router({
  crear: adminProcedure
    .input(
      z.object({
        nombre: z.string().min(2, "Nombre requerido"),
        email: z.string().email("Email inválido"),
        password: z.string().min(8, "Mínimo 8 caracteres"),
        role: z.enum(["admin", "capturista", "consultor", "user"]),
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
        role: input.role,
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

  listar: adminProcedure
    .input(
      z.object({
        search: z.string().optional(),
      }),
    )
    .query(async ({ input }) => {
      const usuarios = await listarUsuarios(input.search);
      return usuarios;
    }),

  cambiarRol: adminProcedure
    .input(
      z.object({
        id: z.number(),
        role: z.enum(["admin", "capturista", "consultor", "user"]),
      }),
    )
    .mutation(async ({ input }) => {
      await cambiarRolUsuario(input.id, input.role);
      return { success: true };
    }),

  toggleActivo: adminProcedure
    .input(
      z.object({
        id: z.number(),
      }),
    )
    .mutation(async ({ input }) => {
      await toggleActivoUsuario(input.id);
      return { success: true };
    }),
});
