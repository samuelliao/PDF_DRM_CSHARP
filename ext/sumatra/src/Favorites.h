/* Copyright 2012 the SumatraPDF project authors (see AUTHORS file).
   License: GPLv3 */

#ifndef Favorites_h
#define Favorites_h

class WindowInfo;

/*
A favorite is a bookmark (we call it a favorite, like Internet Explorer, to
differentiate from bookmarks inside a PDF file (which really are
table of contents)).

We can have multiple favorites per file.

Favorites are accurate to a page - it's simple and should be good enough
for the user.

A favorite is identified by a (mandatory) page number and (optional) name
(provided by the user).

Favorites do not remember presentation settings like zoom or viewing mode -
they are for navigation only. Presentation settings are remembered on a
per-file basis in FileHistory.
*/

class FavName {
public:
   FavName(int pageNo, const WCHAR *name) : pageNo(pageNo), name(NULL)
   {
       SetName(name);
   }

   ~FavName()
   {
       free(name);
   }

   void SetName(const WCHAR *name)
   {
       str::ReplacePtr(&this->name, name);
   }

   int     pageNo;
   WCHAR * name;
   int     menuId; // assigned in AppendFavMenuItems()
};

// list of favorites for one file
class FileFavs {

   int FindByPage(int pageNo) const;

   static int SortByPageNo(const void *a, const void *b);

public:
   WCHAR *         filePath;
   Vec<FavName *>  favNames;

   FileFavs(const WCHAR *fp) : filePath(str::Dup(fp)) { }

   ~FileFavs() {
       DeleteVecMembers(favNames);
       free(filePath);
   }

   bool IsEmpty() const {
       return favNames.Count() == 0;
   }

   bool Exists(int pageNo) const {
       return FindByPage(pageNo) != -1;
   }

   void ResetMenuIds();
   bool GetByMenuId(int menuId, size_t& idx);
   bool HasFavName(FavName *fn);
   bool Remove(int pageNo);
   void AddOrReplace(int pageNo, const WCHAR *name);
};

class Favorites {

   // filePathCache points to a string inside FileFavs, so doesn't need to free()d
   WCHAR *  filePathCache;
   size_t   idxCache;

   void RemoveFav(FileFavs *fav, size_t idx);

public:
   Vec<FileFavs*> favs;

   Favorites() : filePathCache(NULL), idxCache((size_t)-1) { }
   ~Favorites() { DeleteVecMembers(favs); }

   size_t Count() const {
       return favs.Count();
   }


   FileFavs *GetByMenuId(int menuId, size_t& idx);
   FileFavs *GetByFavName(FavName *fn);
   void ResetMenuIds();
   FileFavs *GetFavByFilePath(const WCHAR *filePath, bool createIfNotExist=false, size_t *idx=NULL);
   bool IsPageInFavorites(const WCHAR *filePath, int pageNo);
   void AddOrReplace(const WCHAR *filePath, int pageNo, const WCHAR *name);
   void Remove(const WCHAR *filePath, int pageNo);
   void RemoveAllForFile(const WCHAR *filePath);
};

void AddFavorite(WindowInfo *win);
void DelFavorite(WindowInfo *win);
void RebuildFavMenu(WindowInfo *win, HMENU menu);
void CreateFavorites(WindowInfo *win);
void ToggleFavorites(WindowInfo *win);
void PopulateFavTreeIfNeeded(WindowInfo *win);
void RememberFavTreeExpansionStateForAllWindows();
void GoToFavoriteByMenuId(WindowInfo *win, int wmId);
void UpdateFavoritesTreeForAllWindows();

#endif
