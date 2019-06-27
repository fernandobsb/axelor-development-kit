/*
 * Axelor Business Solutions
 *
 * Copyright (C) 2005-2019 Axelor (<http://axelor.com>).
 *
 * This program is free software: you can redistribute it and/or  modify
 * it under the terms of the GNU Affero General Public License, version 3,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.axelor.dms.db.repo;

import com.axelor.auth.db.Group;
import com.axelor.auth.db.Permission;
import com.axelor.auth.db.User;
import com.axelor.auth.db.repo.PermissionRepository;
import com.axelor.db.JpaRepository;
import com.axelor.dms.db.DMSFile;
import com.axelor.dms.db.DMSPermission;
import com.axelor.i18n.I18n;
import com.google.inject.persist.Transactional;
import javax.inject.Inject;
import javax.persistence.PersistenceException;

public class DMSPermissionRepository extends JpaRepository<DMSPermission> {

  @Inject private PermissionRepository perms;

  public DMSPermissionRepository() {
    super(DMSPermission.class);
  }

  @Transactional
  public void createPermissions() {
    findOrCreateFull();
    findOrCreateWrite();
    findOrCreateRead();
    findOrCreateParent();
    findOrCreateSelf();
    findOrCreateCreate();
    findOrCreateMeta();
    findOrCreatePermFull();
  }

  private Permission findOrCreate(String name, String... args) {
    Permission perm = perms.findByName(name);

    if (perm == null) {
      perm = new Permission();
      perm.setName(name);
      perm.setObject(args.length > 2 ? args[2] : DMSFile.class.getName());
      perm = perms.save(perm);
    }

    perm.setCondition(args.length > 0 ? args[0] : null);
    perm.setConditionParams(args.length > 1 ? args[1] : null);

    return perm;
  }

  private Permission findOrCreateFull() {
    final Permission permission =
        findOrCreate(
            "perm.dms.file.__full__",
            "self.id = ANY(SELECT x.id FROM DMSFile x "
                + "LEFT JOIN x.permissions x_permissions "
                + "LEFT JOIN x_permissions.user x_permissions_user "
                + "LEFT JOIN x_permissions.group x_permissions_group "
                + "LEFT JOIN x_permissions.permission x_permissions_permission "
                + "WHERE (x_permissions_user = ? OR x_permissions_group = ?) "
                + "AND x_permissions_permission.canCreate = true)",
            "__user__, __user__.group");
    permission.setCanCreate(true);
    permission.setCanRead(true);
    permission.setCanWrite(true);
    permission.setCanRemove(true);
    return permission;
  }

  private Permission findOrCreateWrite() {
    final Permission permission =
        findOrCreate(
            "perm.dms.file.__write__",
            "self.id = ANY(SELECT x.id FROM DMSFile x "
                + "LEFT JOIN x.permissions x_permissions "
                + "LEFT JOIN x_permissions.user x_permissions_user "
                + "LEFT JOIN x_permissions.group x_permissions_group "
                + "LEFT JOIN x_permissions.permission x_permissions_permission "
                + "WHERE (x_permissions_user = ? OR x_permissions_group = ?) "
                + "AND x_permissions_permission.canWrite = true)",
            "__user__, __user__.group");
    permission.setCanCreate(false);
    permission.setCanRead(true);
    permission.setCanWrite(true);
    permission.setCanRemove(true);
    return permission;
  }

  private Permission findOrCreateRead() {
    final Permission permission =
        findOrCreate(
            "perm.dms.file.__read__",
            "self.id = ANY(SELECT x.id FROM DMSFile x "
                + "LEFT JOIN x.permissions x_permissions "
                + "LEFT JOIN x_permissions.user x_permissions_user "
                + "LEFT JOIN x_permissions.group x_permissions_group "
                + "LEFT JOIN x_permissions.permission x_permissions_permission "
                + "WHERE (x_permissions_user = ? OR x_permissions_group = ?) "
                + "AND x_permissions_permission.canRead = true)",
            "__user__, __user__.group");
    permission.setCanCreate(false);
    permission.setCanRead(true);
    permission.setCanWrite(false);
    permission.setCanRemove(false);
    return permission;
  }

  private Permission findOrCreateParent() {
    final Permission permission =
        findOrCreate(
            "perm.dms.file.__parent__",
            "self.parent = ANY(SELECT x.id FROM DMSFile x "
                + "LEFT JOIN x.permissions x_permissions "
                + "LEFT JOIN x_permissions.user x_permissions_user "
                + "LEFT JOIN x_permissions.group x_permissions_group "
                + "LEFT JOIN x_permissions.permission x_permissions_permission "
                + "WHERE (x_permissions_user = ? OR x_permissions_group = ?) "
                + "AND x_permissions_permission.canRead = true)",
            "__user__, __user__.group");
    permission.setCanCreate(false);
    permission.setCanRead(true);
    permission.setCanWrite(false);
    permission.setCanRemove(false);
    return permission;
  }

  private Permission findOrCreateSelf() {
    final Permission permission =
        findOrCreate(
            "perm.dms.file.__self__", "self.createdBy = ?", "__user__", DMSFile.class.getName());
    permission.setCanCreate(false);
    permission.setCanRead(true);
    permission.setCanWrite(true);
    permission.setCanRemove(true);
    return permission;
  }

  private Permission findOrCreateCreate() {
    final Permission permission =
        findOrCreate("perm.dms.__create__", null, null, "com.axelor.dms.db.*");
    permission.setCanCreate(true);
    permission.setCanRead(false);
    permission.setCanWrite(false);
    permission.setCanRemove(false);

    return permission;
  }

  private Permission findOrCreateMeta() {
    final Permission permission =
        findOrCreate("perm.meta.file.__create__", null, null, "com.axelor.meta.db.MetaFile");
    permission.setCanCreate(true);
    permission.setCanRead(false);
    permission.setCanWrite(false);
    permission.setCanRemove(false);
    return permission;
  }

  private Permission findOrCreatePermFull() {
    final Permission permission =
        findOrCreate(
            "perm.dms.perm.__full__",
            "self.createdBy = ? OR ((self.user = ? OR self.group = ?) AND self.value = 'FULL')",
            "__user__, __user__, __user__.group",
            DMSPermission.class.getName());
    permission.setCanCreate(true);
    permission.setCanRead(true);
    permission.setCanWrite(true);
    permission.setCanRemove(true);
    return permission;
  }

  @Override
  public DMSPermission save(DMSPermission entity) {

    final DMSFile file = entity.getFile();
    if (file == null) {
      throw new PersistenceException(I18n.get("Invalid permission"));
    }

    final User user = entity.getUser();
    final Group group = entity.getGroup();

    Permission permission = null;

    switch (entity.getValue()) {
      case "FULL":
        permission = findOrCreateFull();
        break;
      case "WRITE":
        permission = findOrCreateWrite();
        break;
      case "READ":
        permission = findOrCreateRead();
        break;
    }

    if (permission == null) {
      return super.save(entity);
    }

    final Permission __self__ = findOrCreateSelf();
    final Permission __create__ = findOrCreateCreate();
    final Permission __meta__ = findOrCreateMeta();
    final Permission __parent__ = findOrCreateParent();
    final Permission __perm_full__ = findOrCreatePermFull();

    if (user != null) {
      user.addPermission(permission);
      user.addPermission(__self__);
      user.addPermission(__create__);
      user.addPermission(__parent__);
      user.addPermission(__meta__);
      user.addPermission(__perm_full__);
    }
    if (group != null) {
      group.addPermission(permission);
      group.addPermission(__self__);
      group.addPermission(__create__);
      group.addPermission(__parent__);
      group.addPermission(__meta__);
      group.addPermission(__perm_full__);
    }

    entity.setPermission(permission);

    return super.save(entity);
  }
}
