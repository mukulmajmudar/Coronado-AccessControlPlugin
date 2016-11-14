from contextlib import closing
from datetime import datetime, timedelta

import argh
from Coronado.Config import Config as ConfigBase
from Coronado.Plugin import AppPlugin as AppPluginBase, \
        CommandLinePlugin as CLPluginBase
import Coronado.Exceptions
import MySQLPlugin

import pymysql

class Forbidden(Exception):
    pass


def defaultVerifier(policy, **kwargs):
    return policy.verify(**kwargs)


class AccessPolicy(object):
    verifier = None
    forbiddenExceptionCls = None

    def __init__(self, verifier=defaultVerifier,
            forbiddenExceptionCls=Forbidden):
        self.verifier = verifier
        self.forbiddenExceptionCls = forbiddenExceptionCls


    def verifyAccess(self, **kwargs):
        return self.verifier(self, **kwargs)


    def verify(self, **kwargs):
        '''
        Access verification logic.
        '''
        raise NotImplementedError()


class ACLAccessPolicy(AccessPolicy):
    '''
    An access policy which ensures that the requester has permission to
    access the requested object.
    '''

    # pylint: disable=too-many-arguments
    def verify(self, **kwargs):
        userId = kwargs['userId']
        objectClass = kwargs['objectClass']
        objectId = kwargs['objectId']
        accessType = kwargs['accessType']
        database = kwargs['database']

        if userId is None:
            raise self.forbiddenExceptionCls()
        
        # Check if the requesting user has access to the requested object
        with closing(database.cursor()) as cursor:
            cursor.execute(
                '''
                SELECT * 
                FROM accessControlObjects, accessControlRules
                WHERE
                    objectClass = %s AND
                    objectId = %s AND
                    accessControlObjects.id = accessCtlObjectId AND
                    granteeId = %s AND accessType = %s
                ''',
                (objectClass, objectId, userId, accessType))

            # If access rule not found, reject access
            row = cursor.fetchone()
            if row is None:
                raise self.forbiddenExceptionCls()

            return row['accessCtlObjectId']


    class Error(Exception):
        pass


    @staticmethod
    # pylint: disable=too-many-arguments
    def grant(objectClass, objectId, granteeId, accessType,
            database=None, cursor=None):
        '''
        Grant access to an access control object.
        '''
        if cursor is None and database is None:
            raise Coronado.Exceptions.MissingArgument(
                'Either database or cursor is required.')

        closeCursor = False
        if cursor is None:
            closeCursor = True
            cursor = database.cursor()

        try:
            # Get access control object ID
            cursor.execute(
                '''
                SELECT id
                FROM accessControlObjects
                WHERE objectClass = %s AND objectId = %s
                ''',
                (objectClass, objectId))
            row = cursor.fetchone()
            if not row:
                raise ACLAccessPolicy.Error('object not found')

            accessCtlObjectId = row['id']

            try:
                cursor.execute(
                    '''
                    INSERT INTO accessControlRules
                    (
                        accessCtlObjectId,
                        granteeId,
                        accessType
                    )
                    VALUES (%s, %s, %s)
                    ''', (accessCtlObjectId, granteeId, accessType))
            except pymysql.IntegrityError:
                pass
        finally:
            if closeCursor:
                cursor.close()


    @staticmethod
    # pylint: disable=too-many-arguments
    def revoke(objectClass, objectId, granteeId, accessType,
            database=None, cursor=None):
        '''
        Revoke access to an access control object.
        '''
        if cursor is None and database is None:
            raise Coronado.Exceptions.MissingArgument(
                'Either database or cursor is required.')

        closeCursor = False
        if cursor is None:
            closeCursor = True
            cursor = database.cursor()

        try:
            # Get access control object ID
            cursor.execute(
                '''
                SELECT id
                FROM accessControlObjects
                WHERE objectClass = %s AND objectId = %s
                ''',
                (objectClass, objectId))
            row = cursor.fetchone()
            if not row:
                raise ACLAccessPolicy.Error('object not found')

            accessCtlObjectId = row['id']

            try:
                cursor.execute(
                    '''
                    DELETE FROM accessControlRules
                    WHERE 
                        accessCtlObjectId = %s AND
                        granteeId = %s AND
                        accessType = %s
                    ''', (accessCtlObjectId, granteeId, accessType))
            except pymysql.IntegrityError:
                pass
        finally:
            if closeCursor:
                cursor.close()


    @staticmethod
    def addAccessCtlObject(database, objectClass, objectId, ownerId,
            transaction=True):
        with closing(database.cursor()) as cursor:
            if transaction:
                cursor.execute('BEGIN')

            try:
                # Create access control object
                cursor.execute('''INSERT INTO accessControlObjects
                    (objectClass, objectId) VALUES (%s, %s)''',
                    (objectClass, objectId))

                # Read new access control object's ID
                acoId = database.insert_id()

                # Set owner
                cursor.execute(
                        'INSERT INTO accessControlOwners VALUES (%s, %s)',
                        (acoId, ownerId))

                # Add access rules: owner has read and edit access
                cursor.executemany('''INSERT INTO accessControlRules
                    (accessCtlObjectId, granteeId, accessType) VALUES
                        (%s, %s, %s)''', 
                    [
                        (acoId, ownerId, 'read'),
                        (acoId, ownerId, 'edit'),
                    ])
            except:
                if transaction:
                    database.rollback()
                raise
            else:
                if transaction:
                    database.commit()

                return acoId


class OwnerAccessPolicy(AccessPolicy):
    '''
    An access policy which ensures that the requester is the owner
    of the requested object.
    '''

    def verify(self, **kwargs):
        userId = kwargs['userId']
        objectClass = kwargs['objectClass']
        objectId = kwargs['objectId']
        database = kwargs['database']
        if userId is None:
            raise self.forbiddenExceptionCls()

        # Check if the requesting user owns the requested object
        with closing(database.cursor()) as cursor:
            cursor.execute(
                '''
                SELECT *
                FROM accessControlObjects, accessControlOwners
                WHERE
                    objectClass = %s AND
                    objectId = %s AND
                    accessControlObjects.id = accessCtlObjectId AND
                    ownerId = %s
                ''',
                (objectClass, objectId, userId))

            # If ownership not found, reject access
            row = cursor.fetchone()
            if row is None:
                raise self.forbiddenExceptionCls()

        return row['accessCtlObjectId']


class Config(ConfigBase):

    def __init__(self, keys=None): 
        if keys is None:
            keys = []
        super().__init__(
        [
            'accessPolicyClasses',
            'accessPolicyVerifier',
            'forbiddenExceptionCls'
        ] + keys)


    def _getAccessPolicyClasses(self):
        '''
        Access policies for the application.
        '''
        return {}

    def _getAccessPolicyVerifier(self):
        '''
        Access policy verifier.
        '''
        return defaultVerifier

    def _getForbiddenExceptionCls(self):
        return Forbidden


aclSchemaV2SQL = \
'''
/**
 * Objects which need access control.
 */
CREATE TABLE accessControlObjects(
    id INT PRIMARY KEY AUTO_INCREMENT,
    objectClass VARCHAR(30) CHARACTER SET utf8 NOT NULL,
    objectId INT NOT NULL,
    UNIQUE(objectClass, objectId)
) ENGINE=INNODB;


/**
 * Owners of access control objects.
 */
CREATE TABLE accessControlOwners(
    accessCtlObjectId INT NOT NULL,
    ownerId INT NOT NULL,
    UNIQUE (accessCtlObjectId, ownerId),
    FOREIGN KEY (ownerId) REFERENCES users(id)
        ON UPDATE CASCADE ON DELETE CASCADE,
    FOREIGN KEY (accessCtlObjectId) REFERENCES accessControlObjects(id)
        ON UPDATE CASCADE ON DELETE CASCADE
) ENGINE=INNODB;


/**
 * Users who have access to access-controlled objects.
 */
CREATE TABLE accessControlRules(
    id INT PRIMARY KEY AUTO_INCREMENT,
    accessCtlObjectId INT NOT NULL,
    granteeId INT NOT NULL,
    accessType VARCHAR(30) CHARACTER SET utf8 NOT NULL,
    UNIQUE(accessCtlObjectId, granteeId, accessType),
    FOREIGN KEY (accessCtlObjectId) REFERENCES accessControlObjects(id)
        ON UPDATE CASCADE ON DELETE CASCADE,
    FOREIGN KEY (granteeId) REFERENCES users(id)
        ON UPDATE CASCADE ON DELETE CASCADE
) ENGINE=INNODB;

CREATE TABLE aclMetadata(
    attribute VARCHAR(100) CHARACTER SET utf8 UNIQUE NOT NULL,
    value VARCHAR(200) CHARACTER SET utf8 NOT NULL
) ENGINE=INNODB;

INSERT INTO aclMetadata VALUES ('version', '2');
'''

upgradeFromV1SQL = \
'''
ALTER TABLE accessControlObjects ADD CONSTRAINT uniqueObjClsId UNIQUE (objectId, objectClass);
UPDATE aclMetadata SET value = '2' WHERE attribute = 'version';
'''

aclSchemaVersion = 2

class SchemaNotInstalled(Exception):
    pass

class SchemaVersionMismatch(Exception):
    pass

class AppPlugin(AppPluginBase):
    context = None

    def getId(self):
        return 'accessControlPlugin'

    # pylint: disable=unused-argument
    def start(self, app, context):
        self.context = context

        with closing(self.context['database'].cursor()) as cursor:
            # Make sure ACL schema has been installed
            cursor.execute('SHOW TABLES LIKE "aclMetadata"')
            if cursor.rowcount == 0:
                raise SchemaNotInstalled('ACL schema not installed.')

            # Make sure schema version is what we expect
            cursor.execute(
                '''
                SELECT value
                FROM aclMetadata
                WHERE attribute = "version"
                ''')
            row = cursor.fetchone()
            if row is None:
                raise SchemaNotInstalled('ACL schema not installed.')
            if row['value'] != str(aclSchemaVersion):
                message = 'ACL schema version {} expected, {} found instead.'
                message = message.format(aclSchemaVersion, row['value'])
                raise SchemaVersionMismatch(message)

        accessPolicyClasses = \
        {
            'aclAccessPolicy': ACLAccessPolicy,
            'ownerAccessPolicy': OwnerAccessPolicy
        }
        accessPolicyClasses.update(context['accessPolicyClasses'])

        # Get access policy verifier
        accessPolicyVerifier = context['accessPolicyVerifier']

        # Get forbidden exception class
        forbiddenExceptionCls = context['forbiddenExceptionCls']

        # Instantiate access policies
        for name, policyCls in accessPolicyClasses.items():
            context[name] = policyCls(
                    verifier=accessPolicyVerifier,
                    forbiddenExceptionCls=forbiddenExceptionCls)
            context['shortcutAttrs'].append(name)


class CommandLinePlugin(MySQLPlugin.CommandLinePlugin):
    context = None

    def getConfig(self):
        cfg = super().getConfig()
        cfg.update(
        {
            'name': 'acl',
            'title': 'ACL operations',
            'commands': 
            [
                self.installSchema,
                self.upgradeSchema,
                self.getSchemaVersion,
                self.grant,
                self.revoke,
                self.addAccessCtlObject
            ],
            'namespace': True
        })
        return cfg


    @argh.arg('-l', '--logLevel', 
            help='one of "debug", "info", "warning", "error", and "critical"')
    @argh.arg('--logFormat', 
            help='Python-like log format (see Python docs for details)')
    def installSchema(self, logLevel='warning',
            logFormat='%(levelname)s:%(name)s (at %(asctime)s): %(message)s'):
        '''
        Install ACL database schema.
        '''
        Coronado.configureLogging(level=logLevel, format=logFormat)
        with closing(MySQLPlugin.getMysqlConnection(self.context)) as db:
            with closing(db.cursor()) as cursor:
                cursor.execute(aclSchemaV2SQL)


    def upgradeSchema(self, logLevel='warning',
            logFormat='%(levelname)s:%(name)s (at %(asctime)s): %(message)s'):
        '''
        Upgrade ACL database schema.
        '''
        Coronado.configureLogging(level=logLevel, format=logFormat)
        currentVersion = self.getSchemaVersion()
        if currentVersion == '2':
            print('Schema version is up to date.')
            return
        elif currentVersion != '1':
            print('Upgrade is only possible from schema version 1, ' +
                'but found installed version {}.'.format(currentVersion))
            return

        with closing(MySQLPlugin.getMysqlConnection(self.context)) as db:
            with closing(db.cursor()) as cursor:
                cursor.execute(upgradeFromV1SQL)

        print('Schema version successfully upgraded to 2.')


    @argh.arg('-l', '--logLevel', 
            help='one of "debug", "info", "warning", "error", and "critical"')
    @argh.arg('--logFormat', 
            help='Python-like log format (see Python docs for details)')
    # pylint: disable=too-many-arguments
    def grant(self, objectClass, objectId, granteeId, accessType,
            logLevel='warning',
            logFormat='%(levelname)s:%(name)s (at %(asctime)s): %(message)s'):
        '''
        Grant access to an object to a user.
        '''
        Coronado.configureLogging(level=logLevel, format=logFormat)
        with closing(MySQLPlugin.getMysqlConnection(self.context)) as db:
            ACLAccessPolicy.grant(objectClass, objectId, granteeId,
                    accessType, database=db)


    @argh.arg('-l', '--logLevel', 
            help='one of "debug", "info", "warning", "error", and "critical"')
    @argh.arg('--logFormat', 
            help='Python-like log format (see Python docs for details)')
    # pylint: disable=too-many-arguments
    def revoke(self, objectClass, objectId, granteeId, accessType,
            logLevel='warning',
            logFormat='%(levelname)s:%(name)s (at %(asctime)s): %(message)s'):
        '''
        Revoke a user's access to an object.
        '''
        Coronado.configureLogging(level=logLevel, format=logFormat)
        with closing(MySQLPlugin.getMysqlConnection(self.context)) as db:
            ACLAccessPolicy.revoke(objectClass, objectId, granteeId,
                    accessType, database=db)


    def getSchemaVersion(self):
        '''
        Get currently installed ACL database schema version.
        '''
        return super().getSchemaVersion('aclMetadata')


    @argh.arg('-l', '--logLevel', 
            help='one of "debug", "info", "warning", "error", and "critical"')
    @argh.arg('--logFormat', 
            help='Python-like log format (see Python docs for details)')
    # pylint: disable=too-many-arguments
    def addAccessCtlObject(self, objectClass, objectId, ownerId,
            logLevel='warning',
            logFormat='%(levelname)s:%(name)s (at %(asctime)s): %(message)s'):

        '''
        Add an access controlled object.
        '''
        Coronado.configureLogging(level=logLevel, format=logFormat)
        with closing(MySQLPlugin.getMysqlConnection(self.context)) as db:
            ACLAccessPolicy.addAccessCtlObject(db, objectClass, objectId,
                    ownerId)
